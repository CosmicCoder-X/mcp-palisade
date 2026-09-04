"""Detections for content that the model reads but a human reviewer will not.

The premise of every rule here: an MCP approval dialog shows a rendered string,
while the model receives the raw bytes. Any gap between those two is not a
formatting quirk, it is a channel.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from palisade import canon
from palisade.models import Confidence, Evidence, Finding, ServerSurface, Severity
from palisade.rules.base import Rule, TextUnit, excerpt, iter_text_units, register

_SPEC_REF = "https://modelcontextprotocol.io/specification"


@register
class HiddenPayloadRule(Rule):
    """Invisible characters that decode to readable text."""

    id = "PAL001"
    title = "Decodable payload hidden in invisible Unicode"
    severity = Severity.CRITICAL
    confidence = Confidence.CERTAIN
    tags = ("concealment", "tool-poisoning")
    references = (_SPEC_REF,)
    remediation = (
        "Reject this server. Text encoded in Unicode tag characters or variation "
        "selectors has no legitimate use in a tool description; its only purpose is "
        "to reach the model without reaching the reviewer."
    )

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            for channel, decoded in canon.decoded_payloads(unit.text):
                preview = decoded if len(decoded) <= 300 else decoded[:300] + "..."
                yield self.finding(
                    unit.subject,
                    f"The {unit.field_path} of {unit.subject} carries {len(decoded)} "
                    f"characters smuggled through the {channel} channel. Decoded, it "
                    f"reads: {preview!r}",
                    [
                        Evidence(
                            unit.field_path,
                            preview,
                            note=f"decoded from {channel}",
                        )
                    ],
                )


@register
class InvisibleCharacterRule(Rule):
    """Non-rendering characters, whether or not they decode to anything."""

    id = "PAL002"
    title = "Non-rendering characters in advertised text"
    severity = Severity.HIGH
    confidence = Confidence.CERTAIN
    tags = ("concealment",)
    remediation = (
        "Strip formatting and private-use characters from descriptions before "
        "publishing. If the server is third-party, treat their presence as hostile "
        "until the maintainer explains them."
    )

    # A stray BOM or a single joiner inside an emoji is noise, not signal.
    MIN_RUN = 2
    BENIGN_SINGLETONS = {0xFEFF, 0x200D}

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            runs = canon.find_invisibles(unit.text)
            if not runs:
                continue

            interesting = [
                r
                for r in runs
                if r.length >= self.MIN_RUN
                or set(r.codepoints) - self.BENIGN_SINGLETONS
                and r.kind in (canon.InvisibleKind.BIDI, canon.InvisibleKind.TAG)
            ]
            if not interesting:
                continue

            total = sum(r.length for r in interesting)
            ratio = canon.hidden_ratio(unit.text)
            severity = Severity.HIGH if total >= 8 else Severity.MEDIUM

            evidence = []
            for run in interesting[:5]:
                snippet, s, e = excerpt(canon.visualize(unit.text), run.start, run.end)
                evidence.append(
                    Evidence(
                        unit.field_path,
                        snippet,
                        s,
                        e,
                        note=f"{run.length}x {run.kind}: {', '.join(run.names()[:3])}",
                    )
                )

            yield self.finding(
                unit.subject,
                f"The {unit.field_path} of {unit.subject} contains {total} non-rendering "
                f"characters across {len(interesting)} run(s), {ratio:.0%} of the field. "
                f"A reviewer approving this tool sees none of them.",
                evidence,
                severity=severity,
            )


@register
class MixedScriptRule(Rule):
    """Homoglyph words that impersonate a different identifier."""

    id = "PAL003"
    title = "Mixed-script word (homoglyph impersonation)"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("concealment", "impersonation")
    remediation = (
        "Confirm each flagged identifier is genuinely multilingual. Tool names should "
        "be restricted to a single script; clients compare them as exact strings, so a "
        "confusable name defeats allow-lists and pin stores."
    )

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            for hit in canon.find_mixed_script_words(unit.text):
                confusable = "".join(
                    f"U+{ord(c):04X}" if canon.script_of(c) != "Latin" else c for c in hit.word
                )
                severity = Severity.CRITICAL if unit.field_path == "name" else self.severity
                yield self.finding(
                    unit.subject,
                    f"The word {hit.word!r} in the {unit.field_path} of {unit.subject} "
                    f"mixes {' and '.join(hit.scripts)} characters. It renders like an "
                    f"ordinary word but is a distinct string: {confusable}.",
                    [
                        Evidence(
                            unit.field_path,
                            hit.word,
                            hit.start,
                            hit.end,
                            note=f"scripts: {', '.join(hit.scripts)}",
                        )
                    ],
                    severity=severity,
                )


@register
class BuriedTextRule(Rule):
    """Content pushed out of sight by whitespace or sheer length."""

    id = "PAL004"
    title = "Text buried below a whitespace gap or excessive length"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("concealment", "tool-poisoning")
    remediation = (
        "Read the full raw description, not the rendered one. Legitimate tools "
        "document themselves in a paragraph; padding exists to push instructions "
        "past the edge of a scroll box."
    )

    GAP = re.compile(r"(?:[ \t]*\r?\n){4,}|[ \t]{40,}")
    LONG_DESCRIPTION = 2000

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            if unit.field_path == "name":
                continue

            m = self.GAP.search(unit.text)
            if m and unit.text[m.end():].strip():
                trailing = unit.text[m.end():].strip()
                preview = trailing if len(trailing) <= 300 else trailing[:300] + "..."
                yield self.finding(
                    unit.subject,
                    f"The {unit.field_path} of {unit.subject} hides {len(trailing)} "
                    f"characters after a run of whitespace. Content below the gap: "
                    f"{preview!r}",
                    [Evidence(unit.field_path, preview, m.end(), len(unit.text), note="after gap")],
                )
                continue

            if len(unit.text) > self.LONG_DESCRIPTION and unit.field_path == "description":
                yield self.finding(
                    unit.subject,
                    f"The description of {unit.subject} is {len(unit.text)} characters. "
                    f"Approval dialogs truncate long descriptions, so the tail is "
                    f"delivered to the model but never shown to the user.",
                    [
                        Evidence(
                            unit.field_path,
                            unit.text[-300:],
                            note="final 300 characters",
                        )
                    ],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                )


@register
class MarkupConcealmentRule(Rule):
    """Instructions wrapped in markup that a renderer drops."""

    id = "PAL005"
    title = "Content concealed inside markup"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("concealment", "tool-poisoning")
    remediation = (
        "Remove HTML comments and hidden elements from descriptions. Clients that "
        "render Markdown will drop them from the display while the model still "
        "receives them in full."
    )

    PATTERNS: tuple[tuple[str, str], ...] = (
        ("an HTML comment", r"<!--(?P<body>.*?)-->"),
        ("an element hidden with CSS", r"<[^>]+style\s*=\s*[\"'][^\"']*display\s*:\s*none[^>]*>"),
        ("a zero-opacity element", r"<[^>]+style\s*=\s*[\"'][^\"']*opacity\s*:\s*0[^>]*>"),
        ("an ANSI escape sequence", r"\x1b\[[0-9;]*[A-Za-z]"),
    )

    def __init__(self) -> None:
        self._compiled = [
            (label, re.compile(pat, re.IGNORECASE | re.DOTALL)) for label, pat in self.PATTERNS
        ]

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            for label, rx in self._compiled:
                for m in rx.finditer(unit.text):
                    body = (m.groupdict().get("body") or m.group()).strip()
                    if len(body) < 8:
                        continue
                    snippet, s, e = excerpt(unit.text, m.start(), m.end())
                    yield self.finding(
                        unit.subject,
                        f"The {unit.field_path} of {unit.subject} conceals content inside "
                        f"{label}. Hidden content: {body[:200]!r}",
                        [Evidence(unit.field_path, snippet, s, e, note=label)],
                    )
                    break


__all__ = [
    "HiddenPayloadRule",
    "InvisibleCharacterRule",
    "MixedScriptRule",
    "BuriedTextRule",
    "MarkupConcealmentRule",
    "TextUnit",
]
