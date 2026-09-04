"""Detections for capability that the schema fails to bound.

These findings are about blast radius rather than intent. A server can be
entirely honest and still hand the model a parameter that accepts any shell
command, and an injection landing anywhere else in the context will happily
use it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from palisade.models import Confidence, Evidence, Finding, ServerSurface, Severity
from palisade.rules.base import Rule, register
from palisade.rules.exfiltration import iter_properties

_CONSTRAINT_KEYS = ("enum", "const", "pattern", "format", "maxLength", "oneOf", "anyOf")


@register
class UnconstrainedCapabilityRule(Rule):
    """Dangerous parameters that accept arbitrary strings."""

    id = "PAL040"
    title = "High-impact parameter accepts unconstrained input"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("capability", "hardening")
    remediation = (
        "Constrain the parameter with an enum, pattern or format. An unbounded "
        "command, path or URL field converts any successful prompt injection "
        "anywhere in the context into code or file access on the host."
    )

    DANGEROUS = {
        "command": ("command execution", Severity.CRITICAL),
        "cmd": ("command execution", Severity.CRITICAL),
        "shell": ("command execution", Severity.CRITICAL),
        "exec": ("command execution", Severity.CRITICAL),
        "script": ("code execution", Severity.CRITICAL),
        "code": ("code execution", Severity.CRITICAL),
        "eval": ("code execution", Severity.CRITICAL),
        "sql": ("query injection", Severity.CRITICAL),
        "path": ("filesystem access", Severity.HIGH),
        "file": ("filesystem access", Severity.HIGH),
        "filepath": ("filesystem access", Severity.HIGH),
        "file_path": ("filesystem access", Severity.HIGH),
        "filename": ("filesystem access", Severity.HIGH),
        "directory": ("filesystem access", Severity.HIGH),
        "dir": ("filesystem access", Severity.HIGH),
        "url": ("server-side request forgery", Severity.HIGH),
        "uri": ("server-side request forgery", Severity.HIGH),
        "endpoint": ("server-side request forgery", Severity.HIGH),
        "host": ("server-side request forgery", Severity.MEDIUM),
        "target": ("server-side request forgery", Severity.MEDIUM),
    }

    # Several dangerous-looking names have an overwhelmingly common innocent
    # sense. Flagging "code" on every tool that takes a country code trains
    # people to ignore the rule, so the innocent sense is checked for first.
    BENIGN_SENSE = {
        "code": re.compile(
            r"\b(country|currency|postal|zip|area|airport|dial|language|locale|"
            r"status|error|promo|discount|coupon|invite|referral|verification|"
            r"otp|two[- ]factor|region|state|iata|icao|hs|sic|naics)\b",
            re.IGNORECASE,
        ),
        "target": re.compile(
            r"\b(element|selector|audience|goal|metric|column|field)\b", re.IGNORECASE
        ),
        "host": re.compile(r"\b(hostname\s+to\s+display|label|nickname)\b", re.IGNORECASE),
    }

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for tool in surface.tools:
            for path, name, prop in iter_properties(tool.input_schema):
                lowered = name.lower()
                entry = self.DANGEROUS.get(lowered)
                if not entry:
                    continue
                if prop.get("type") not in (None, "string"):
                    continue
                if any(k in prop for k in _CONSTRAINT_KEYS):
                    continue
                benign = self.BENIGN_SENSE.get(lowered)
                if benign and benign.search(prop.get("description") or ""):
                    continue
                impact, severity = entry
                yield self.finding(
                    f"tool: {tool.name}",
                    f"Parameter {name!r} of {tool.name!r} is an unconstrained string "
                    f"that the tool name and shape suggest is used for {impact}. "
                    f"Nothing in the schema limits what the model may put there.",
                    [
                        Evidence(
                            path,
                            f"{name}: {prop.get('type', 'string')} (no "
                            f"{'/'.join(_CONSTRAINT_KEYS[:4])})",
                            note=impact,
                        )
                    ],
                    severity=severity,
                )


@register
class UnboundedSchemaRule(Rule):
    """Schemas that place no limit on what may be sent."""

    id = "PAL042"
    title = "Tool input schema is unbounded"
    severity = Severity.MEDIUM
    confidence = Confidence.FIRM
    tags = ("capability", "hardening")
    remediation = (
        "Declare the properties the tool accepts and set additionalProperties to "
        "false. An open schema means a client cannot tell a user what a call will "
        "actually send."
    )

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for tool in surface.tools:
            schema = tool.input_schema or {}
            props = schema.get("properties")

            if schema.get("additionalProperties") is True:
                yield self.finding(
                    f"tool: {tool.name}",
                    f"The schema for {tool.name!r} sets additionalProperties to true, "
                    f"so arbitrary extra fields can be attached to any call without "
                    f"appearing in the tool's documented interface.",
                    [Evidence("inputSchema.additionalProperties", "true")],
                )
            elif schema and not props:
                yield self.finding(
                    f"tool: {tool.name}",
                    f"The schema for {tool.name!r} declares no properties, so the "
                    f"client cannot show the user what this tool will be called with.",
                    [Evidence("inputSchema", "no properties declared")],
                    severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE,
                )


@register
class MissingAnnotationRule(Rule):
    """State-changing tools that do not declare themselves as such.

    MCP's behavioural hints are what let a client decide when to interrupt the
    user for confirmation. A write-capable tool that omits them is treated as
    ordinary, which is exactly the mistake an attacker wants the client to make.
    """

    id = "PAL041"
    title = "State-changing tool omits behavioural annotations"
    severity = Severity.MEDIUM
    confidence = Confidence.TENTATIVE
    tags = ("hardening", "annotations")
    remediation = (
        "Declare readOnlyHint, destructiveHint and idempotentHint on every tool. "
        "Clients rely on them to decide what needs explicit confirmation."
    )

    # Letter-only lookarounds rather than \b: tool names are snake_case, and an
    # underscore is a word character, so \brun\b never matches "run_task".
    # The suffix group covers the inflections these verbs actually appear in
    # ("executes", "deleted", "uploading") without matching "input" or "output".
    MUTATING = re.compile(
        r"(?<![A-Za-z])"
        r"(write|create|update|delete|remove|drop|send|post|put|patch|execute|run|"
        r"deploy|publish|move|rename|modify|edit|insert|upload|purge|revoke|grant)"
        r"(?:e?[sd]|ing)?"
        r"(?![A-Za-z])",
        re.IGNORECASE,
    )
    HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for tool in surface.tools:
            annotations = tool.annotations or {}
            if any(h in annotations for h in self.HINTS):
                continue
            m = self.MUTATING.search(tool.name) or self.MUTATING.search(tool.description or "")
            if not m:
                continue
            yield self.finding(
                f"tool: {tool.name}",
                f"{tool.name!r} appears to change state (matched {m.group()!r}) but "
                f"declares none of the MCP behavioural hints. A client has no basis "
                f"for asking the user to confirm it.",
                [Evidence("annotations", "none declared", note=f"verb: {m.group()}")],
            )


__all__ = ["UnconstrainedCapabilityRule", "UnboundedSchemaRule", "MissingAnnotationRule"]
