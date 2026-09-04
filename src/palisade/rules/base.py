"""Rule abstractions and the shared text-unit view of a surface.

Every rule sees the same normalised stream of ``TextUnit`` objects, so a rule
author never has to remember that a malicious instruction can hide in a nested
JSON-Schema property description just as easily as in a tool's summary.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from palisade.canon import iter_text_fields
from palisade.models import Confidence, Evidence, Finding, ServerSurface, Severity

_REGISTRY: list[type[Rule]] = []


def register(cls: type[Rule]) -> type[Rule]:
    """Class decorator that adds a rule to the default rule set."""
    _REGISTRY.append(cls)
    return cls


def all_rules() -> list[Rule]:
    return [cls() for cls in sorted(_REGISTRY, key=lambda c: c.id)]


@dataclass(frozen=True)
class TextUnit:
    """One string drawn from the surface, tagged with where it came from.

    ``subject`` is the thing a reader cares about ("tool: send_email");
    ``field_path`` is the precise location inside it.
    """

    subject: str
    field_path: str
    text: str
    kind: str  # tool | prompt | resource | server


def iter_text_units(surface: ServerSurface) -> Iterator[TextUnit]:
    """Flatten a surface into every attacker-controlled string it contains."""
    if surface.instructions:
        yield TextUnit("server instructions", "instructions", surface.instructions, "server")

    for tool in surface.tools:
        subject = f"tool: {tool.name}"
        yield TextUnit(subject, "name", tool.name, "tool")
        if tool.description:
            yield TextUnit(subject, "description", tool.description, "tool")
        for path, text in iter_text_fields(tool.input_schema, "inputSchema"):
            yield TextUnit(subject, path, text, "tool")
        for path, text in iter_text_fields(tool.annotations, "annotations"):
            yield TextUnit(subject, path, text, "tool")

    for prompt in surface.prompts:
        subject = f"prompt: {prompt.name}"
        yield TextUnit(subject, "name", prompt.name, "prompt")
        if prompt.description:
            yield TextUnit(subject, "description", prompt.description, "prompt")
        for path, text in iter_text_fields(prompt.arguments, "arguments"):
            yield TextUnit(subject, path, text, "prompt")

    for resource in surface.resources:
        subject = f"resource: {resource.name or resource.uri}"
        yield TextUnit(subject, "uri", resource.uri, "resource")
        if resource.description:
            yield TextUnit(subject, "description", resource.description, "resource")


def excerpt(text: str, start: int, end: int, pad: int = 40) -> tuple[str, int, int]:
    """Cut a readable window around a match, returned with adjusted offsets."""
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(text) else ""
    return f"{prefix}{text[lo:hi]}{suffix}", start - lo + len(prefix), end - lo + len(prefix)


class Rule(ABC):
    """Base class for every detection.

    Subclasses declare their identity as class attributes and implement
    :meth:`check`. Severity is a class default; a rule may still downgrade or
    upgrade an individual finding when it has reason to.
    """

    id: str = "PAL000"
    title: str = "unnamed rule"
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.FIRM
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    remediation: str = ""

    @abstractmethod
    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        """Yield a finding for every problem this rule sees in ``surface``."""

    # -- helpers available to every rule ---------------------------------

    def finding(
        self,
        subject: str,
        description: str,
        evidence: list[Evidence] | None = None,
        *,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        remediation: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            subject=subject,
            description=description,
            remediation=remediation or self.remediation,
            evidence=evidence or [],
            references=list(self.references),
            tags=list(self.tags),
        )


class PatternRule(Rule):
    """A rule driven by a table of labelled regular expressions.

    Signature tables live next to the rule they serve rather than in one global
    blob, so adding a detection means adding a row and a test.
    """

    patterns: tuple[tuple[str, str], ...] = ()  # (label, regex)
    flags: int = re.IGNORECASE
    applies_to_kinds: tuple[str, ...] = ("tool", "prompt", "resource", "server")
    skip_field_names: bool = True

    def __init__(self) -> None:
        self._compiled = [(label, re.compile(pat, self.flags)) for label, pat in self.patterns]

    def describe_hit(self, label: str, unit: TextUnit) -> str:
        return (
            f"The {unit.field_path} of {unit.subject} contains {label}. Descriptions are "
            f"consumed verbatim by the model, so text of this shape functions as an "
            f"instruction rather than documentation."
        )

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            if unit.kind not in self.applies_to_kinds:
                continue
            if self.skip_field_names and unit.field_path == "name":
                continue
            for label, rx in self._compiled:
                for m in rx.finditer(unit.text):
                    snippet, s, e = excerpt(unit.text, m.start(), m.end())
                    yield self.finding(
                        unit.subject,
                        self.describe_hit(label, unit),
                        [Evidence(unit.field_path, snippet, s, e, note=label)],
                    )
                    break  # one finding per pattern per field is enough
