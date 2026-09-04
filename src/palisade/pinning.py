"""Trust-on-first-use pinning for server surfaces.

Static analysis only ever sees the surface a server chooses to show at that
moment. A server that serves clean descriptions during review and swaps them
afterwards defeats every rule in the analyser, and nothing in MCP requires a
client to notice. Pinning closes that gap: hash what was approved, compare on
every later connection, and treat any drift as a security event until a human
says otherwise.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from palisade.canon import canonical_json, digest, visualize
from palisade.models import (
    Confidence,
    Evidence,
    Finding,
    ServerSurface,
    Severity,
    ToolDescriptor,
)


def default_store_path() -> Path:
    """Pin database location, overridable for tests and CI."""
    env = os.environ.get("PALISADE_HOME")
    base = Path(env) if env else Path.home() / ".palisade"
    return base / "pins.json"


def tool_digest(tool: ToolDescriptor) -> str:
    return digest(
        tool.name,
        tool.description,
        canonical_json(tool.input_schema),
        canonical_json(tool.annotations),
    )


def surface_digest(surface: ServerSurface) -> str:
    return digest(
        *(tool_digest(t) for t in sorted(surface.tools, key=lambda t: t.name)),
        canonical_json([p.to_dict() for p in surface.prompts]),
        canonical_json([r.to_dict() for r in surface.resources]),
        surface.instructions,
    )


@dataclass
class ToolPin:
    name: str
    digest: str
    description: str
    schema_json: str

    @classmethod
    def from_tool(cls, tool: ToolDescriptor) -> ToolPin:
        return cls(
            name=tool.name,
            digest=tool_digest(tool),
            description=tool.description,
            schema_json=canonical_json(tool.input_schema),
        )


@dataclass
class ServerPin:
    server_id: str
    surface_digest: str
    first_pinned: str
    last_verified: str
    origin: str = ""
    tools: dict[str, ToolPin] = field(default_factory=dict)

    @classmethod
    def from_surface(cls, surface: ServerSurface) -> ServerPin:
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            server_id=surface.server_id,
            surface_digest=surface_digest(surface),
            first_pinned=now,
            last_verified=now,
            origin=surface.origin,
            tools={t.name: ToolPin.from_tool(t) for t in surface.tools},
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tools"] = {k: asdict(v) for k, v in self.tools.items()}
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ServerPin:
        return cls(
            server_id=d["server_id"],
            surface_digest=d["surface_digest"],
            first_pinned=d["first_pinned"],
            last_verified=d.get("last_verified", d["first_pinned"]),
            origin=d.get("origin", ""),
            tools={k: ToolPin(**v) for k, v in d.get("tools", {}).items()},
        )


class PinStore:
    """A small JSON-backed database of approved surfaces."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_store_path()
        self._pins: dict[str, ServerPin] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        self._pins = {k: ServerPin.from_dict(v) for k, v in data.get("servers", {}).items()}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "servers": {k: v.to_dict() for k, v in self._pins.items()},
        }
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    def get(self, server_id: str) -> ServerPin | None:
        return self._pins.get(server_id)

    def pin(self, surface: ServerSurface) -> ServerPin:
        pin = ServerPin.from_surface(surface)
        existing = self._pins.get(surface.server_id)
        if existing:
            pin.first_pinned = existing.first_pinned
        self._pins[surface.server_id] = pin
        return pin

    def forget(self, server_id: str) -> bool:
        return self._pins.pop(server_id, None) is not None

    def __len__(self) -> int:
        return len(self._pins)

    def __iter__(self) -> Iterable[ServerPin]:
        return iter(self._pins.values())


# --------------------------------------------------------------------------
# Drift detection
# --------------------------------------------------------------------------


@dataclass
class Change:
    kind: str  # added | removed | modified
    tool: str
    field_name: str = ""
    before: str = ""
    after: str = ""


def diff_surface(pin: ServerPin, surface: ServerSurface) -> list[Change]:
    """Compare a live surface against what was approved."""
    changes: list[Change] = []
    live = {t.name: t for t in surface.tools}

    for name in sorted(set(live) - set(pin.tools)):
        changes.append(Change("added", name))
    for name in sorted(set(pin.tools) - set(live)):
        changes.append(Change("removed", name))

    for name in sorted(set(pin.tools) & set(live)):
        pinned, tool = pin.tools[name], live[name]
        if tool_digest(tool) == pinned.digest:
            continue
        if tool.description != pinned.description:
            changes.append(
                Change("modified", name, "description", pinned.description, tool.description)
            )
        schema_now = canonical_json(tool.input_schema)
        if schema_now != pinned.schema_json:
            changes.append(Change("modified", name, "inputSchema", pinned.schema_json, schema_now))
    return changes


def verify(
    pin: ServerPin,
    surface: ServerSurface,
    rescan_severity: Severity | None = None,
) -> list[Finding]:
    """Turn surface drift into findings.

    ``rescan_severity`` is the worst severity the analyser found when run over
    only the changed text. Drift that introduces a new high-severity detection
    is a different event from a maintainer fixing a typo, and is reported as
    such.
    """
    findings: list[Finding] = []
    changes = diff_surface(pin, surface)
    if not changes:
        return findings

    escalate = rescan_severity is not None and rescan_severity.rank >= Severity.HIGH.rank

    for change in changes:
        if change.kind == "added":
            findings.append(
                Finding(
                    rule_id="PAL051",
                    title="Tool appeared after the server was approved",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    subject=f"tool: {change.tool}",
                    description=(
                        f"{change.tool!r} was not present when this server was pinned on "
                        f"{pin.first_pinned}. It has not been reviewed."
                    ),
                    remediation=(
                        "Review the new tool, then re-pin with 'palisade pin' to accept it."
                    ),
                    evidence=[Evidence("name", change.tool, note="not in pin")],
                    tags=["rug-pull", "drift"],
                )
            )
        elif change.kind == "removed":
            findings.append(
                Finding(
                    rule_id="PAL052",
                    title="Approved tool disappeared",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    subject=f"tool: {change.tool}",
                    description=(
                        f"{change.tool!r} was pinned but is no longer advertised. A server "
                        f"varying its surface between connections may be serving different "
                        f"clients different tools."
                    ),
                    remediation="Confirm the removal is intentional, then re-pin.",
                    evidence=[Evidence("name", change.tool, note="present in pin only")],
                    tags=["rug-pull", "drift"],
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="PAL050",
                    title="Approved tool definition changed",
                    severity=Severity.CRITICAL if escalate else Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    subject=f"tool: {change.tool}",
                    description=(
                        f"The {change.field_name} of {change.tool!r} differs from the "
                        f"version approved on {pin.first_pinned}. "
                        + (
                            "The new text triggers a high-severity detection, which is "
                            "the signature of a rug pull: benign at review, hostile "
                            "afterwards."
                            if escalate
                            else "Review the change before continuing to use this server."
                        )
                    ),
                    remediation=(
                        "Do not use the server until the change is explained. Re-pin only "
                        "after reviewing the new definition in full."
                    ),
                    evidence=[
                        Evidence(
                            change.field_name,
                            visualize(change.before, max_len=400),
                            note="approved version",
                        ),
                        Evidence(
                            change.field_name,
                            visualize(change.after, max_len=400),
                            note="current version",
                        ),
                    ],
                    tags=["rug-pull", "drift"],
                )
            )
    return findings


def changed_surface(pin: ServerPin, surface: ServerSurface) -> ServerSurface:
    """A surface containing only what changed, for re-analysis."""
    changed_names = {c.tool for c in diff_surface(pin, surface) if c.kind != "removed"}
    return ServerSurface(
        server_id=surface.server_id,
        transport=surface.transport,
        origin=surface.origin,
        tools=[t for t in surface.tools if t.name in changed_names],
    )
