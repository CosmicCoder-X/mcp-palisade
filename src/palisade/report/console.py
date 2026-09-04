"""Human-facing output.

Reports are written to be acted on: every finding says what was seen, quotes
the exact text that triggered it with invisible characters made visible, and
ends with the decision the reader has to make.
"""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from palisade.models import Finding, ScanReport, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_BORDER = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "grey50",
}


def severity_badge(severity: Severity) -> Text:
    return Text(f" {severity.value.upper()} ", style=SEVERITY_STYLE[severity])


def console_safe(text: str, console: Console) -> str:
    """Make ``text`` printable on ``console`` without losing information.

    Palisade exists to display text that is hostile on purpose, so output
    routinely contains code points the terminal cannot encode -- a Windows
    console defaulting to cp1252 cannot print the Cyrillic characters in a
    homoglyph attack. Escaping those to ``\\uXXXX`` is strictly better than
    crashing, and for a confusable character it is arguably the more honest
    rendering anyway.
    """
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
        return text
    except (UnicodeEncodeError, LookupError):
        return text.encode(encoding, errors="backslashreplace").decode(encoding, "replace")


def render_finding(finding: Finding, console: Console) -> None:
    header = Text()
    header.append_text(severity_badge(finding.severity))
    header.append(f"  {finding.rule_id}  ", style="bold")
    header.append(finding.title, style="bold white")

    body: list[object] = [Text(console_safe(finding.description, console), style="")]

    if finding.evidence:
        table = Table(show_header=True, header_style="dim", box=None, padding=(0, 1))
        table.add_column("field", style="cyan", no_wrap=True, max_width=34)
        table.add_column("evidence", overflow="fold")
        for ev in finding.evidence:
            safe = console_safe(ev.snippet, console)
            snippet = Text(safe)
            # Offsets index the original string. If escaping changed the text,
            # the span no longer lines up, so highlight nothing rather than
            # underlining the wrong characters.
            if safe == ev.snippet and 0 <= ev.start < ev.end <= len(safe):
                snippet.stylize("bold reverse", ev.start, ev.end)
            if ev.note:
                snippet.append(f"\n[{ev.note}]", style="dim italic")
            table.add_row(ev.field_path, snippet)
        body.append(Text(""))
        body.append(table)

    if finding.remediation:
        body.append(Text(""))
        body.append(Text(finding.remediation, style="italic green"))

    meta = Text(
        f"confidence: {finding.confidence.value}   "
        f"fingerprint: {finding.fingerprint}"
        + (f"   tags: {', '.join(finding.tags)}" if finding.tags else ""),
        style="dim",
    )
    body.append(Text(""))
    body.append(meta)

    console.print(
        Panel(
            Group(*body),
            title=header,
            title_align="left",
            subtitle=Text(console_safe(finding.subject, console), style="bold magenta"),
            subtitle_align="right",
            border_style=SEVERITY_BORDER[finding.severity],
            padding=(1, 2),
        )
    )
    console.print()


def render_report(report: ScanReport, console: Console | None = None, quiet: bool = False) -> None:
    console = console or Console()
    surface = report.surface

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim", justify="right")
    meta.add_column()
    meta.add_row("server", Text(surface.server_id, style="bold"))
    if surface.server_name:
        meta.add_row("name", f"{surface.server_name} {surface.server_version}".strip())
    meta.add_row("transport", surface.transport)
    if surface.origin:
        meta.add_row("origin", surface.origin)
    meta.add_row(
        "surface",
        f"{len(surface.tools)} tools, {len(surface.prompts)} prompts, "
        f"{len(surface.resources)} resources",
    )
    meta.add_row("rules", str(report.rules_run))
    console.print(Panel(meta, title="[bold]palisade[/bold]", title_align="left", padding=(1, 2)))
    console.print()

    if not report.findings:
        console.print("  [green]No findings.[/green] The advertised surface looks clean.\n")
        console.print(
            "  [dim]Static analysis sees only what the server chose to send. Run "
            "'palisade pin' to detect later changes.[/dim]\n"
        )
        return

    if not quiet:
        for finding in report.sorted_findings():
            render_finding(finding, console)

    counts = report.counts()
    summary = Table(box=None, padding=(0, 2))
    summary.add_column("severity")
    summary.add_column("count", justify="right")
    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        if counts[sev.value]:
            summary.add_row(
                Text(sev.value.upper(), style=SEVERITY_STYLE[sev]), str(counts[sev.value])
            )
    console.print(
        Panel(
            summary,
            title=f"[bold]{len(report.findings)} findings[/bold]",
            title_align="left",
            border_style=SEVERITY_BORDER[report.worst] if report.worst else "grey50",
            padding=(1, 2),
        )
    )
    console.print()


def render_cross_findings(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()
    if not findings:
        return
    console.rule("[bold]cross-server findings[/bold]")
    console.print()
    for finding in sorted(findings, key=lambda f: -f.severity.rank):
        render_finding(finding, console)
