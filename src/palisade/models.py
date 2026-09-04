"""Core data model.

Palisade analyses a *surface*: the set of tools, prompts and resources that an
MCP server advertises to a client. The surface is deliberately decoupled from
the transport that produced it, so the analyser can run against a live server,
a captured JSON bundle, or a hand-written fixture without changing a line of
rule code.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How bad this is if the finding is a true positive."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    # All four comparisons are defined explicitly. Severity subclasses ``str``
    # so that it serialises cleanly, which means it inherits str's ordering:
    # without these, ``max()`` compares the names alphabetically and decides
    # that "medium" outranks "critical".
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """How sure we are that the pattern we matched means what we think.

    Kept separate from severity on purpose. A hidden Unicode payload is
    low-severity-if-benign but we are *certain* it is there; an unusual
    parameter name is a real risk but we are guessing.
    """

    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


@dataclass(frozen=True)
class Evidence:
    """A located, quotable justification for a finding.

    ``start``/``end`` are character offsets into the referenced field so that
    reporters can underline the exact span rather than dumping a whole tool
    description.
    """

    field_path: str
    snippet: str
    start: int = -1
    end: int = -1
    note: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    subject: str
    description: str
    remediation: str
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable identity for baselining, so a triaged finding stays suppressed."""
        spans = "|".join(f"{e.field_path}:{e.snippet}" for e in self.evidence)
        raw = f"{self.rule_id}\x00{self.subject}\x00{spans}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ToolDescriptor:
    """One advertised tool, exactly as the server presented it."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ToolDescriptor:
        return cls(
            name=d.get("name", ""),
            description=d.get("description") or "",
            input_schema=d.get("inputSchema") or d.get("input_schema") or {},
            annotations=d.get("annotations") or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
        }


@dataclass
class PromptDescriptor:
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PromptDescriptor:
        return cls(
            name=d.get("name", ""),
            description=d.get("description") or "",
            arguments=d.get("arguments") or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "arguments": self.arguments}


@dataclass
class ResourceDescriptor:
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ResourceDescriptor:
        return cls(
            uri=d.get("uri", ""),
            name=d.get("name") or "",
            description=d.get("description") or "",
            mime_type=d.get("mimeType") or d.get("mime_type") or "",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
        }


@dataclass
class ServerSurface:
    """Everything a client learns about a server before it decides to trust it."""

    server_id: str
    transport: str = "unknown"
    origin: str = ""
    server_name: str = ""
    server_version: str = ""
    captured_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tools: list[ToolDescriptor] = field(default_factory=list)
    prompts: list[PromptDescriptor] = field(default_factory=list)
    resources: list[ResourceDescriptor] = field(default_factory=list)
    instructions: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ServerSurface:
        meta = d.get("server", d)
        return cls(
            server_id=meta.get("id") or meta.get("server_id") or "unknown",
            transport=meta.get("transport", "unknown"),
            origin=meta.get("origin", ""),
            server_name=meta.get("name", ""),
            server_version=meta.get("version", ""),
            captured_at=d.get("captured_at", datetime.now(timezone.utc).isoformat()),
            tools=[ToolDescriptor.from_dict(t) for t in d.get("tools", [])],
            prompts=[PromptDescriptor.from_dict(p) for p in d.get("prompts", [])],
            resources=[ResourceDescriptor.from_dict(r) for r in d.get("resources", [])],
            instructions=d.get("instructions") or "",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": {
                "id": self.server_id,
                "transport": self.transport,
                "origin": self.origin,
                "name": self.server_name,
                "version": self.server_version,
            },
            "captured_at": self.captured_at,
            "instructions": self.instructions,
            "tools": [t.to_dict() for t in self.tools],
            "prompts": [p.to_dict() for p in self.prompts],
            "resources": [r.to_dict() for r in self.resources],
        }

    @classmethod
    def load(cls, path: str) -> ServerSurface:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


@dataclass
class ScanReport:
    surface: ServerSurface
    findings: list[Finding] = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    rules_run: int = 0

    @property
    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.rule_id, f.subject))

    def to_dict(self) -> dict[str, Any]:
        from palisade import __version__

        return {
            "palisade_version": __version__,
            "scanned_at": self.scanned_at,
            "server": self.surface.to_dict()["server"],
            "summary": {
                "rules_run": self.rules_run,
                "total_findings": len(self.findings),
                "by_severity": self.counts(),
                "worst_severity": self.worst.value if self.worst else None,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
