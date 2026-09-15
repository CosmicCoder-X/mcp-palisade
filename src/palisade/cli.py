"""Command line interface.

Exit codes are chosen for CI: 0 clean, 1 findings at or above the failure
threshold, 2 an operational error such as an unreachable server.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from palisade import __version__
from palisade.connect import ConnectError, ServerSpec, introspect, load_client_config
from palisade.engine import Baseline, Engine
from palisade.models import ScanReport, ServerSurface, Severity
from palisade.pinning import PinStore, changed_surface, verify
from palisade.report import console as console_report
from palisade.report import sarif as sarif_report
from palisade.rules import all_rules
from palisade.rules.semantic import DEFAULT_PROVIDER as DEFAULT_SEMANTIC_PROVIDER
from palisade.rules.semantic import RULE_METADATA as SEMANTIC_RULE_METADATA
from palisade.rules.semantic import SemanticAnalysisError, SemanticJudge

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Security scanner for Model Context Protocol servers.",
)


def _force_utf8_output() -> None:
    """Stop the host terminal's encoding from truncating a report.

    Reports quote hostile text verbatim, and on Windows the default console
    encoding is cp1252, which cannot represent the Cyrillic and tag-block code
    points this tool exists to surface. Escaping is a last resort; widening the
    stream first keeps the output faithful.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):  # not a reconfigurable text stream
            pass


_force_utf8_output()

err = Console(stderr=True)
out = Console()

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        raise typer.BadParameter(
            f"{value!r} is not a severity. Choose from: "
            + ", ".join(s.value for s in Severity)
        ) from None


def _resolve_surfaces(
    targets: list[str] | None,
    config: Path | None,
    stdio: str | None,
    url: str | None,
    sse: bool,
    name: str | None,
    timeout: float,
) -> list[ServerSurface]:
    """Turn whatever the user supplied into surfaces to analyse."""
    chosen = [bool(targets), bool(config), bool(stdio), bool(url)]
    if sum(chosen) != 1:
        raise typer.BadParameter(
            "Give exactly one target: captured surface file(s), --config, --stdio or --url."
        )

    if targets:
        surfaces = []
        for target in targets:
            path = Path(target)
            if not path.exists():
                raise typer.BadParameter(f"{target}: no such file")
            surfaces.append(ServerSurface.load(str(path)))
        return surfaces

    if config:
        specs = load_client_config(config)
        if not specs:
            raise typer.BadParameter(f"{config}: no servers found")
        _warn_execution(specs)
        surfaces = []
        for spec in specs:
            try:
                surfaces.append(introspect(spec, timeout))
            except Exception as exc:
                err.print(f"[yellow]skipping {spec.id}: {exc}[/yellow]")
        if not surfaces:
            raise ConnectError("no server could be reached")
        return surfaces

    if stdio:
        spec = ServerSpec.from_stdio(name or "stdio-server", stdio)
        _warn_execution([spec])
        return [introspect(spec, timeout)]

    spec = ServerSpec.from_url(name or "remote-server", url or "", "sse" if sse else "http")
    return [introspect(spec, timeout)]


def _warn_execution(specs: list[ServerSpec]) -> None:
    stdio_specs = [s for s in specs if s.transport == "stdio"]
    if stdio_specs:
        err.print(
            "[yellow]note:[/yellow] capturing a stdio server executes it. "
            f"Launching: {', '.join(s.origin for s in stdio_specs)}"
        )


@app.command()
def scan(
    targets: list[str] | None = typer.Argument(
        None,
        help="One or more captured surface JSON files. Passing several enables "
        "cross-server rules.",
    ),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Host MCP config to enumerate and capture live."
    ),
    stdio: str | None = typer.Option(
        None, "--stdio", help="Command line of a stdio server, e.g. 'npx -y some-server'."
    ),
    url: str | None = typer.Option(None, "--url", help="URL of a remote MCP server."),
    sse: bool = typer.Option(False, "--sse", help="Use the SSE transport for --url."),
    name: str | None = typer.Option(None, "--name", help="Server id to record."),
    fmt: str = typer.Option("text", "--format", "-f", help="text, json or sarif."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to a file."),
    fail_on: str = typer.Option("high", "--fail-on", help="Minimum severity that exits 1."),
    min_severity: str = typer.Option(
        "info", "--min-severity", help="Drop findings below this severity."
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", "-b", help="Baseline file of accepted fingerprints."
    ),
    disable: list[str] = typer.Option([], "--disable", "-d", help="Rule id to skip. Repeatable."),
    check_pins: bool = typer.Option(
        True, "--check-pins/--no-check-pins", help="Also report drift from a stored pin."
    ),
    semantic: bool = typer.Option(
        False,
        "--semantic",
        help="Also send the surface to an LLM judge that classifies intent rather "
        "than matching patterns. Costs money and needs a provider API key -- see "
        "palisade.rules.semantic.",
    ),
    semantic_provider: str = typer.Option(
        DEFAULT_SEMANTIC_PROVIDER,
        "--semantic-provider",
        help="Backend for --semantic: 'anthropic' (needs ANTHROPIC_API_KEY) or "
        "'gemini' (needs GOOGLE_API_KEY).",
    ),
    semantic_model: str | None = typer.Option(
        None,
        "--semantic-model",
        help="Model for --semantic. Defaults per provider if omitted.",
    ),
    semantic_effort: str | None = typer.Option(
        None,
        "--semantic-effort",
        help="Effort level for --semantic (low..max). Anthropic only.",
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Per-server capture timeout."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Summary only."),
) -> None:
    """Analyse one or more MCP servers and report what they advertise."""
    try:
        surfaces = _resolve_surfaces(targets, config, stdio, url, sse, name, timeout)
    except (ConnectError, OSError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    engine = Engine(
        baseline=Baseline.load(str(baseline) if baseline else None),
        min_severity=_severity(min_severity),
        disabled=frozenset(d.upper() for d in disable),
    )
    reports, cross = engine.scan_workspace(surfaces)

    if check_pins:
        store = PinStore()
        for report in reports:
            pin = store.get(report.surface.server_id)
            if not pin:
                continue
            delta = engine.scan(changed_surface(pin, report.surface))
            report.findings.extend(verify(pin, report.surface, delta.worst))

    if semantic:
        try:
            judge = SemanticJudge(
                provider=semantic_provider, model=semantic_model, effort=semantic_effort
            )
        except SemanticAnalysisError as exc:
            err.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(EXIT_ERROR) from None
        for report in reports:
            try:
                result = judge.analyze(report.surface)
            except SemanticAnalysisError as exc:
                err.print(f"[yellow]semantic analysis skipped for "
                          f"{report.surface.server_id}: {exc}[/yellow]")
                continue
            report.findings.extend(engine.filter_findings(result.findings))
            report.rules_run += len(SEMANTIC_RULE_METADATA)
            err.print(f"[dim]semantic ({report.surface.server_id}): {result.usage_line()}[/dim]")

    threshold = _severity(fail_on)
    worst = max(
        (r.worst for r in reports if r.worst),
        default=None,
    )
    cross_worst = max((f.severity for f in cross), default=None)
    if cross_worst and (not worst or cross_worst.rank > worst.rank):
        worst = cross_worst

    _emit(reports, cross, fmt, output, quiet, semantic)

    if worst and worst.rank >= threshold.rank:
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_OK)


def _emit(
    reports: list[ScanReport],
    cross: list,
    fmt: str,
    output: Path | None,
    quiet: bool,
    semantic: bool = False,
) -> None:
    fmt = fmt.lower()
    if fmt == "text":
        target_console = Console(file=output.open("w", encoding="utf-8")) if output else out
        for report in reports:
            console_report.render_report(report, target_console, quiet=quiet)
        console_report.render_cross_findings(cross, target_console)
        if output:
            target_console.file.close()
            out.print(f"[green]wrote[/green] {output}")
        return

    if fmt == "json":
        payload = {
            "servers": [r.to_dict() for r in reports],
            "cross_server_findings": [f.to_dict() for f in cross],
        }
    elif fmt == "sarif":
        extra_meta = SEMANTIC_RULE_METADATA if semantic else ()
        payload = sarif_report.build(reports, cross, extra_meta)
    else:
        raise typer.BadParameter(f"unknown format {fmt!r}; use text, json or sarif")

    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if output:
        output.write_text(text + "\n", encoding="utf-8")
        out.print(f"[green]wrote[/green] {output}")
    else:
        sys.stdout.write(text + "\n")


@app.command()
def capture(
    stdio: str | None = typer.Option(None, "--stdio", help="Command line of a stdio server."),
    url: str | None = typer.Option(None, "--url", help="URL of a remote MCP server."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Host MCP config."),
    sse: bool = typer.Option(False, "--sse"),
    name: str | None = typer.Option(None, "--name"),
    output: Path = typer.Option(..., "--output", "-o", help="Where to write the surface JSON."),
    timeout: float = typer.Option(30.0, "--timeout"),
) -> None:
    """Record a server's advertised surface to a file for offline review."""
    try:
        surfaces = _resolve_surfaces(None, config, stdio, url, sse, name, timeout)
    except (ConnectError, OSError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    payload = (
        surfaces[0].to_dict() if len(surfaces) == 1 else [s.to_dict() for s in surfaces]
    )
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out.print(f"[green]captured[/green] {len(surfaces)} server(s) to {output}")


@app.command()
def pin(
    target: str | None = typer.Argument(None, help="Captured surface JSON."),
    stdio: str | None = typer.Option(None, "--stdio"),
    url: str | None = typer.Option(None, "--url"),
    config: Path | None = typer.Option(None, "--config", "-c"),
    sse: bool = typer.Option(False, "--sse"),
    name: str | None = typer.Option(None, "--name"),
    timeout: float = typer.Option(30.0, "--timeout"),
) -> None:
    """Approve the current surface so later changes are detected."""
    try:
        surfaces = _resolve_surfaces(
            [target] if target else None, config, stdio, url, sse, name, timeout
        )
    except (ConnectError, OSError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    store = PinStore()
    for surface in surfaces:
        record = store.pin(surface)
        out.print(
            f"[green]pinned[/green] {surface.server_id} "
            f"({len(surface.tools)} tools) {record.surface_digest[:16]}"
        )
    store.save()
    out.print(f"[dim]stored in {store.path}[/dim]")


@app.command()
def pins() -> None:
    """List pinned servers."""
    store = PinStore()
    if not len(store):
        out.print("[dim]no pins yet[/dim]")
        return
    table = Table(title="pinned servers", box=None, padding=(0, 2))
    table.add_column("server", style="bold")
    table.add_column("tools", justify="right")
    table.add_column("digest", style="dim")
    table.add_column("first pinned", style="dim")
    for record in store:
        table.add_row(
            record.server_id,
            str(len(record.tools)),
            record.surface_digest[:16],
            record.first_pinned[:19],
        )
    out.print(table)
    out.print(f"[dim]{store.path}[/dim]")


@app.command()
def forget(server_id: str = typer.Argument(..., help="Server id to unpin.")) -> None:
    """Remove a pin."""
    store = PinStore()
    if store.forget(server_id):
        store.save()
        out.print(f"[green]forgot[/green] {server_id}")
    else:
        err.print(f"[yellow]no pin for {server_id}[/yellow]")
        raise typer.Exit(EXIT_ERROR)


@app.command()
def baseline(
    target: str = typer.Argument(..., help="Captured surface JSON."),
    output: Path = typer.Option(Path(".palisade-baseline.json"), "--output", "-o"),
) -> None:
    """Accept every current finding, so CI only reports new ones."""
    surface = ServerSurface.load(target)
    report = Engine().scan(surface)
    Baseline.from_report(report).save(str(output))
    out.print(f"[green]baselined[/green] {len(report.findings)} findings to {output}")


@app.command()
def rules() -> None:
    """List the detections Palisade ships with."""
    table = Table(box=None, padding=(0, 2))
    table.add_column("id", style="bold cyan")
    table.add_column("severity")
    table.add_column("title")
    table.add_column("tags", style="dim")
    for rule in all_rules():
        table.add_row(
            rule.id,
            console_report.severity_badge(rule.severity),
            rule.title,
            ", ".join(rule.tags),
        )
    out.print(table)
    out.print(f"[dim]{len(all_rules())} rules[/dim]")
    out.print(
        f"[dim]+ {len(SEMANTIC_RULE_METADATA)} semantic rules (PAL06x), opt-in via "
        f"--semantic, need ANTHROPIC_API_KEY[/dim]"
    )


@app.command()
def version() -> None:
    """Print the version."""
    out.print(f"palisade {__version__}")


if __name__ == "__main__":
    app()
