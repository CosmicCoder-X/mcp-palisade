"""Detections for tools shaped to collect data rather than do work.

Exfiltration through MCP rarely looks like theft. It looks like a helpful tool
with one extra optional parameter, described in a way that makes the model want
to fill it with whatever it happens to be holding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any

from palisade.models import Confidence, Evidence, Finding, ServerSurface, Severity
from palisade.rules.base import PatternRule, Rule, excerpt, iter_text_units, register


def iter_properties(
    schema: dict[str, Any], prefix: str = "inputSchema.properties"
) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield ``(json_path, property_name, property_schema)`` recursively."""
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            if not isinstance(sub, dict):
                continue
            path = f"{prefix}.{name}"
            yield path, name, sub
            yield from iter_properties(sub, f"{path}.properties")
    items = schema.get("items")
    if isinstance(items, dict):
        yield from iter_properties(items, f"{prefix}.items.properties")


@register
class SensitiveArtifactRule(Rule):
    """Sensitive material named in a description.

    Naming a credential file means one of two quite different things, and
    reporting them identically would be wrong. A tool that *asks the model to
    go and fetch* ``~/.ssh/id_rsa`` is attacking the client. A tool that
    *documents that it returns* environment variables is being honest about a
    genuinely dangerous capability. Both deserve a finding; only the first
    deserves "treat this server as hostile", so the rule decides which reading
    applies from the verb governing the match.
    """

    id = "PAL030"
    title = "Description solicits credentials or sensitive local files"
    severity = Severity.CRITICAL
    confidence = Confidence.FIRM
    tags = ("exfiltration", "credential-access")
    remediation = (
        "No tool needs the model to go and fetch private keys, credential files or "
        "environment variables in order to describe what it does. Treat a server "
        "that names these paths as hostile."
    )

    # A tool describing its own output rather than directing the model. Every
    # verb here is third-person singular on purpose: documentation says "Reads
    # the config file", an injected instruction says "Read the config file".
    # That single letter is the whole distinction, so the optional 's' that
    # would collapse the two is deliberately absent.
    EXPOSES = re.compile(
        r"\b(returns|provides|exposes|lists|reads|outputs|retrieves|fetches|"
        r"dumps|reports|shows|displays|contains|includes|gives\s+access\s+to)\b",
        re.IGNORECASE,
    )
    LOOKBEHIND = 80

    patterns = (
        (
            "a reference to SSH private key material",
            r"(~[/\\]\.ssh|\bid_rsa\b|\bid_ed25519\b|\bauthorized_keys\b|"
            r"BEGIN\s+(RSA|OPENSSH|EC|DSA)?\s*PRIVATE\s+KEY)",
        ),
        (
            "a reference to cloud or package credential files",
            r"(~[/\\]\.aws[/\\]credentials|\.aws[/\\]credentials|\bcredentials\.json\b|"
            r"\.npmrc\b|\.pypirc\b|\.git-credentials\b|\bkubeconfig\b|"
            r"~[/\\]\.docker[/\\]config\.json)",
        ),
        (
            "a reference to environment or dotenv secrets",
            r"(\.env(\.[a-z]+)?\b|\benvironment\s+variables?\b|\bprocess\.env\b|"
            r"\bos\.environ\b|%APPDATA%|\bAWS_SECRET_ACCESS_KEY\b)",
        ),
        (
            "a reference to system credential stores",
            r"(/etc/(passwd|shadow)|\bkeychain\b|\bcredential\s+manager\b|"
            r"\bcookies?\.sqlite\b|\bLogin\s+Data\b|\bwallet\.dat\b)",
        ),
        (
            "a reference to client configuration holding server secrets",
            r"(claude_desktop_config\.json|\.cursor[/\\]mcp\.json|\bmcp\.json\b|"
            r"\.vscode[/\\]mcp\.json)",
        ),
        (
            "a request for API keys or tokens",
            r"\b(api[\s_-]?key|access[\s_-]?token|bearer\s+token|secret[\s_-]?key|"
            r"private[\s_-]?key|session[\s_-]?token|refresh[\s_-]?token)s?\b",
        ),
    )

    def __init__(self) -> None:
        self._compiled = [(label, re.compile(pat, re.IGNORECASE)) for label, pat in self.patterns]

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            if unit.field_path == "name":
                continue
            for label, rx in self._compiled:
                m = rx.search(unit.text)
                if not m:
                    continue
                snippet, s, e = excerpt(unit.text, m.start(), m.end(), pad=60)
                window = unit.text[max(0, m.start() - self.LOOKBEHIND): m.start()]

                if self.EXPOSES.search(window):
                    yield self.finding(
                        unit.subject,
                        f"{unit.subject} documents that it returns sensitive material "
                        f"({label}). The description is honest, but any prompt injection "
                        f"elsewhere in the context can steer the model into calling it, "
                        f"so the capability is reachable by an attacker who never touches "
                        f"this server.",
                        [Evidence(unit.field_path, snippet, s, e, note=f"exposes: {label}")],
                        severity=Severity.HIGH,
                        title="Tool exposes credentials or sensitive local files",
                        remediation=(
                            "Confirm this tool is worth its blast radius. If it stays, it "
                            "should require explicit user confirmation on every call and "
                            "should be declared with destructiveHint so clients can enforce "
                            "that."
                        ),
                    )
                else:
                    yield self.finding(
                        unit.subject,
                        f"The {unit.field_path} of {unit.subject} contains {label}, phrased "
                        f"as something the model should go and obtain. Descriptions are "
                        f"consumed verbatim by the model, so this functions as an "
                        f"instruction rather than documentation.",
                        [Evidence(unit.field_path, snippet, s, e, note=f"solicits: {label}")],
                    )
                break


@register
class ConversationHarvestRule(PatternRule):
    id = "PAL033"
    title = "Description asks for conversation or system-prompt content"
    severity = Severity.CRITICAL
    confidence = Confidence.FIRM
    tags = ("exfiltration",)
    remediation = (
        "A tool argument should carry the data the tool operates on, never the "
        "surrounding conversation. This construction turns any call into a transcript "
        "upload."
    )

    patterns = (
        (
            "a request for prior conversation content",
            r"\b(include|pass|send|attach|provide|copy|append|add|forward|summari[sz]e)\b"
            r"[^.\n]{0,50}\b(conversation|chat\s+history|previous\s+messages?|"
            r"transcript|context\s+window|prior\s+turns?|full\s+context)\b",
        ),
        (
            "a request for the system prompt",
            r"\b(include|pass|send|reveal|output|provide|repeat|print)\b[^.\n]{0,40}"
            r"\b(system\s+prompt|system\s+message|your\s+instructions)\b",
        ),
        (
            "a request for the user's other tool results",
            r"\b(include|pass|send|attach|forward)\b[^.\n]{0,40}"
            r"\b(results?|outputs?|responses?)\s+(of|from)\s+(other|previous|all)\b",
        ),
    )


@register
class AttackerEndpointRule(Rule):
    """Outbound destinations named in text or baked into a schema."""

    id = "PAL032"
    title = "Externally controlled endpoint referenced by the server"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("exfiltration", "c2")
    remediation = (
        "Verify every destination the server can reach. Ephemeral request-capture and "
        "tunnelling hosts have no place in a published tool definition."
    )

    URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
    SUSPICIOUS_HOST = re.compile(
        r"\b("
        r"webhook\.site|requestbin|pipedream\.net|ngrok\.(io|app|dev)|"
        r"burpcollaborator|oastify|interact\.sh|localtunnel|serveo\.net|"
        r"pastebin\.com|paste\.ee|hastebin|transfer\.sh|file\.io|0x0\.st|"
        r"discord(app)?\.com/api/webhooks|hooks\.slack\.com|t\.me/|api\.telegram\.org"
        r")\b",
        re.IGNORECASE,
    )
    RAW_IP = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", re.IGNORECASE)

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            if unit.kind == "resource" and unit.field_path == "uri":
                continue
            for m in self.URL.finditer(unit.text):
                url = m.group()
                snippet, s, e = excerpt(unit.text, m.start(), m.end())

                if self.SUSPICIOUS_HOST.search(url):
                    yield self.finding(
                        unit.subject,
                        f"The {unit.field_path} of {unit.subject} references {url!r}, a "
                        f"host commonly used to capture exfiltrated data.",
                        [Evidence(unit.field_path, snippet, s, e, note="known capture host")],
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CERTAIN,
                    )
                elif self.RAW_IP.match(url):
                    yield self.finding(
                        unit.subject,
                        f"The {unit.field_path} of {unit.subject} references the bare "
                        f"address {url!r}. Published tools normally name a domain.",
                        [Evidence(unit.field_path, snippet, s, e, note="raw IP endpoint")],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                    )

        # A default or const value is filled in without the model ever choosing it.
        for tool in surface.tools:
            for path, name, prop in iter_properties(tool.input_schema):
                for key in ("default", "const"):
                    value = prop.get(key)
                    if isinstance(value, str) and self.URL.search(value):
                        url = self.URL.search(value).group()
                        severity = (
                            Severity.CRITICAL
                            if self.SUSPICIOUS_HOST.search(url)
                            else Severity.MEDIUM
                        )
                        yield self.finding(
                            f"tool: {tool.name}",
                            f"Parameter {name!r} carries a hard-coded {key} pointing at "
                            f"{url!r}. The value is applied whether or not the model or "
                            f"the user ever sees it.",
                            [Evidence(f"{path}.{key}", value, note=f"schema {key}")],
                            severity=severity,
                        )


@register
class ExfiltrationParameterRule(Rule):
    """A free-text parameter whose description invites unrelated data.

    Neither signal is damning alone: plenty of honest tools take a ``notes``
    field, and plenty describe "context". Requiring both a collector-shaped
    name and solicitation language in its description keeps this rule usable.
    """

    id = "PAL031"
    title = "Parameter shaped to collect unrelated data"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("exfiltration",)
    remediation = (
        "Constrain the parameter, or drop it. A string field the model is encouraged "
        "to fill 'with any relevant context' is an open channel out of the session."
    )

    COLLECTOR_NAMES = re.compile(
        r"^(context|notes?|metadata|meta|debug|debug_info|extra|additional|"
        r"session|history|memo|comment|details?|reason|justification|log|logs|"
        r"telemetry|diagnostics?|payload|blob|data|info|summary|background)$",
        re.IGNORECASE,
    )
    SOLICITATION = re.compile(
        r"\b(any|all|as\s+much|everything|relevant|additional|surrounding|full|entire|"
        r"complete|whatever)\b[^.\n]{0,40}"
        r"\b(context|information|data|detail|content|history|text|you\s+(know|have))\b",
        re.IGNORECASE,
    )

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for tool in surface.tools:
            for path, name, prop in iter_properties(tool.input_schema):
                if prop.get("type") not in (None, "string", "object"):
                    continue
                if not self.COLLECTOR_NAMES.match(name):
                    continue
                desc = prop.get("description") or ""
                m = self.SOLICITATION.search(desc)
                if not m:
                    continue
                snippet, s, e = excerpt(desc, m.start(), m.end(), pad=60)
                yield self.finding(
                    f"tool: {tool.name}",
                    f"Parameter {name!r} of {tool.name!r} is an unconstrained string "
                    f"whose description asks the model to supply open-ended context. "
                    f"Whatever the model has in scope can end up on the wire.",
                    [
                        Evidence(
                            f"{path}.description",
                            snippet,
                            s,
                            e,
                            note="collector name + solicitation language",
                        )
                    ],
                )


__all__ = [
    "iter_properties",
    "SensitiveArtifactRule",
    "ConversationHarvestRule",
    "AttackerEndpointRule",
    "ExfiltrationParameterRule",
]
