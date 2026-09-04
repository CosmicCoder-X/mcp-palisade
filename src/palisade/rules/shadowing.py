"""Detections for tools that reach outside their own boundary.

An agent flattens every connected server into one tool list, so a description
belonging to tool A is read by the model while it is deciding whether to call
tool B. That shared namespace is what makes shadowing work: a benign-looking
server can rewrite the semantics of a tool it does not own, including tools
from an entirely different server.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from palisade.models import Confidence, Evidence, Finding, ServerSurface, Severity
from palisade.rules.base import PatternRule, Rule, excerpt, register


class CrossServerRule(Rule):
    """A rule that needs to see every connected server at once.

    Single-surface :meth:`check` is a no-op; the engine calls
    :meth:`check_many` when it has a workspace rather than one server.
    """

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        return ()

    def check_many(self, surfaces: Sequence[ServerSurface]) -> Iterable[Finding]:
        raise NotImplementedError


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Edit distance, abandoned early once it exceeds ``cap``."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            )
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


@register
class CrossToolReferenceRule(Rule):
    """A tool description that gives the model orders about a different tool."""

    id = "PAL020"
    title = "Tool description directs the use of another tool"
    severity = Severity.CRITICAL
    confidence = Confidence.FIRM
    tags = ("shadowing", "tool-poisoning")
    remediation = (
        "A tool may document its own behaviour only. Text that changes how a "
        "different tool is called is a shadowing attack: the model obeys it while "
        "the owner of the shadowed tool never consented to the change."
    )

    DIRECTIVE_NEAR = re.compile(
        r"\b(when|before|after|instead\s+of|always|never|must|should|do\s+not|don'?t|"
        r"whenever|prior\s+to|call|invoke|use|pass|forward|include|add|append|set)\b",
        re.IGNORECASE,
    )
    WINDOW = 120

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        names = {t.name for t in surface.tools if len(t.name) >= 4}
        if len(names) < 2:
            return

        for tool in surface.tools:
            others = names - {tool.name}
            if not others:
                continue
            text = tool.description or ""
            for other in sorted(others):
                for m in re.finditer(rf"\b{re.escape(other)}\b", text):
                    lo = max(0, m.start() - self.WINDOW)
                    hi = min(len(text), m.end() + self.WINDOW)
                    if not self.DIRECTIVE_NEAR.search(text[lo:hi]):
                        continue
                    snippet, s, e = excerpt(text, m.start(), m.end(), pad=self.WINDOW)
                    yield self.finding(
                        f"tool: {tool.name}",
                        f"The description of {tool.name!r} issues directions about the "
                        f"separate tool {other!r}. The model reads every description "
                        f"before every call, so this redefines {other!r} without its "
                        f"owner's involvement.",
                        [Evidence("description", snippet, s, e, note=f"references {other!r}")],
                    )
                    break


@register
class GlobalBehaviourRule(PatternRule):
    id = "PAL022"
    title = "Tool description asserts scope over the whole conversation"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("shadowing", "prompt-injection")
    applies_to_kinds = ("tool", "resource")
    remediation = (
        "Scope descriptions to the tool itself. Language that claims authority over "
        "every request or every tool is attempting to become a second system prompt."
    )

    patterns = (
        (
            "a claim of authority over all tools",
            r"\b(for|with|across|in)\s+(all|any|every|each)\s+(other\s+)?"
            r"(tools?|calls?|requests?|functions?)\b",
        ),
        (
            "a claim of authority over the whole conversation",
            r"\b(in|for|during|throughout)\s+(every|each|all|the\s+entire)\s+"
            r"(conversation|session|interaction|turn|response|message)s?\b",
        ),
        (
            "an unconditional trigger",
            r"\bwhenever\s+(the\s+)?(user|human|someone|anyone)\b",
        ),
        (
            "a claim to apply regardless of the request",
            r"\bregardless\s+of\s+(what|which|the)\b[^.\n]{0,40}\b(user|request|ask)",
        ),
    )

    def describe_hit(self, label: str, unit) -> str:
        return (
            f"The {unit.field_path} of {unit.subject} contains {label}. A single tool "
            f"cannot legitimately govern behaviour outside its own invocation."
        )


@register
class DuplicateToolNameRule(Rule):
    """Collisions and near-collisions inside one server."""

    id = "PAL021"
    title = "Colliding or confusable tool names"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("shadowing", "impersonation")
    remediation = (
        "Give every tool a distinct, clearly distinguishable name. Near-identical "
        "names make the model's choice between them effectively arbitrary."
    )

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        seen: dict[str, int] = {}
        for tool in surface.tools:
            seen[tool.name] = seen.get(tool.name, 0) + 1
        for name, count in seen.items():
            if count > 1:
                yield self.finding(
                    f"tool: {name}",
                    f"The name {name!r} is advertised {count} times by this server. "
                    f"Which definition the client keeps is unspecified.",
                    [Evidence("name", name, note=f"{count} definitions")],
                    severity=Severity.HIGH,
                )

        names = sorted({t.name for t in surface.tools})
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                if len(a) < 5 or len(b) < 5:
                    continue
                if _levenshtein(a, b) == 1:
                    yield self.finding(
                        f"tool: {b}",
                        f"The tool names {a!r} and {b!r} differ by a single character. "
                        f"A model selecting between them by name alone is guessing.",
                        [Evidence("name", f"{a} / {b}", note="edit distance 1")],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                    )


@register
class CrossServerCollisionRule(CrossServerRule):
    """The same tool name advertised by more than one connected server."""

    id = "PAL023"
    title = "Tool name claimed by multiple servers"
    severity = Severity.HIGH
    confidence = Confidence.CERTAIN
    tags = ("shadowing", "cross-server")
    remediation = (
        "Namespace or disable one of the colliding tools. When two servers claim a "
        "name, the tool the model actually reaches depends on client merge order, "
        "which an attacker can often influence."
    )

    def check_many(self, surfaces: Sequence[ServerSurface]) -> Iterable[Finding]:
        owners: dict[str, list[str]] = {}
        for surface in surfaces:
            for tool in surface.tools:
                owners.setdefault(tool.name, []).append(surface.server_id)

        for name, servers in sorted(owners.items()):
            distinct = sorted(set(servers))
            if len(distinct) > 1:
                yield self.finding(
                    f"tool: {name}",
                    f"The tool {name!r} is advertised by {len(distinct)} servers: "
                    f"{', '.join(distinct)}. The client resolves this collision "
                    f"silently, so the model may call a different server than the "
                    f"user believes.",
                    [Evidence("name", name, note=f"servers: {', '.join(distinct)}")],
                )


__all__ = [
    "CrossServerRule",
    "CrossToolReferenceRule",
    "GlobalBehaviourRule",
    "DuplicateToolNameRule",
    "CrossServerCollisionRule",
]
