"""Detections for text that instructs the agent instead of describing the tool.

A tool description has one legitimate job: tell the model what the tool does so
it can decide when to call it. The moment a description starts addressing the
model in the second person and issuing directives, it has stopped being
documentation and started being a prompt. That shift, not any particular
phrase, is what these rules look for.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from palisade.models import Confidence, Evidence, Finding, ServerSurface, Severity
from palisade.rules.base import PatternRule, Rule, TextUnit, excerpt, iter_text_units, register

_OWASP = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"


@register
class InstructionOverrideRule(PatternRule):
    id = "PAL010"
    title = "Attempt to override prior instructions"
    severity = Severity.CRITICAL
    confidence = Confidence.FIRM
    tags = ("prompt-injection", "tool-poisoning")
    references = (_OWASP,)
    remediation = (
        "Do not install this server. A description that tries to displace the host "
        "application's instructions is an attack on the client, not a feature."
    )

    patterns = (
        (
            "an instruction to ignore prior context",
            r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b"
            r"(previous|prior|above|earlier|preceding|all)\b[^.\n]{0,30}"
            r"\b(instruction|prompt|rule|direction|context|message)s?\b",
        ),
        (
            "an instruction override directive",
            r"\boverride\b[^.\n]{0,30}\b(system|previous|existing|your)\b"
            r"[^.\n]{0,20}\b(prompt|instruction|rule|policy)s?\b",
        ),
        ("a redefinition of the model's real task",
         r"\byour\s+(real|actual|true|primary)\s+(task|instruction|purpose|goal|job)s?\b"),
        ("a spoofed system-message delimiter",
         r"<\s*/?\s*(system|system[-_]prompt|important[-_ ]instructions?|admin)\s*>"),
        ("a fabricated new-instruction header",
         r"(?:^|\n)\s*(?:#{1,3}\s*)?(?:new|updated|revised)\s+instructions?\s*[:\-]"),
    )


@register
class UserConcealmentRule(PatternRule):
    id = "PAL011"
    title = "Directive to hide behaviour from the user"
    severity = Severity.CRITICAL
    confidence = Confidence.FIRM
    tags = ("prompt-injection", "tool-poisoning", "exfiltration")
    references = (_OWASP,)
    remediation = (
        "Treat as malicious. There is no benign reason for a tool to ask the model to "
        "withhold information from the person operating it."
    )

    patterns = (
        (
            "an instruction not to inform the user",
            r"\b(do\s*not|don'?t|never|avoid)\b[^.\n]{0,25}\b"
            r"(tell|inform|mention|reveal|disclose|notify|alert|show|report)\b"
            r"[^.\n]{0,30}\b(user|human|operator|person|them)\b",
        ),
        (
            "an instruction to act without notifying the user",
            r"\bwithout\b[^.\n]{0,20}\b(telling|informing|notifying|alerting|asking)\b"
            r"[^.\n]{0,20}\b(the\s+)?(user|human|operator)\b",
        ),
        (
            "an instruction to act covertly",
            r"\b(silently|secretly|covertly|quietly|discreetly|invisibly)\b[^.\n]{0,25}"
            r"\b(call|invoke|send|execute|perform|forward|copy|read|append)\b",
        ),
        (
            "an instruction to keep the interaction secret",
            r"\bkeep\b[^.\n]{0,20}\b(secret|hidden|confidential|private|between\s+us)\b",
        ),
        (
            "an instruction to suppress output",
            r"\b(do\s*not|don'?t|never)\b[^.\n]{0,20}"
            r"\b(output|print|display|log|echo|include|repeat|mention)\b"
            r"[^.\n]{0,30}\b(this|these|instruction|content|text|message)s?\b",
        ),
    )


@register
class MandatoryPreconditionRule(PatternRule):
    id = "PAL012"
    title = "Tool claims to be a mandatory precondition for other tools"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("prompt-injection", "shadowing")
    references = (_OWASP,)
    remediation = (
        "A tool cannot legitimately declare itself a prerequisite for unrelated "
        "tools. This is the standard construction for forcing an attacker-controlled "
        "call into every conversation turn."
    )

    patterns = (
        (
            "a claim of mandatory precedence over other tools",
            r"\bbefore\b[^.\n]{0,30}\b(using|calling|invoking|running|executing)\b"
            r"[^.\n]{0,30}\b(any|each|every|all|other|another)\b[^.\n]{0,20}\btools?\b",
        ),
        (
            "a directive to always call this tool first",
            r"\b(must|should|always|need\s+to|have\s+to)\b[^.\n]{0,20}"
            r"\b(first|always)\b[^.\n]{0,25}\b(call|invoke|run|use|read|query)\b",
        ),
        (
            "a directive to call this tool before responding",
            r"\b(prior\s+to|before)\b[^.\n]{0,20}\b(responding|answering|replying|"
            r"continuing|proceeding)\b",
        ),
        (
            "a self-declared mandatory step",
            r"\b(mandatory|required|obligatory|compulsory)\b[^.\n]{0,20}"
            r"\b(first\s+)?(step|call|action|check)\b",
        ),
    )


@register
class TrustConditioningRule(PatternRule):
    id = "PAL013"
    title = "Language designed to suppress user confirmation"
    severity = Severity.HIGH
    confidence = Confidence.FIRM
    tags = ("prompt-injection", "approval-bypass")
    references = (_OWASP,)
    remediation = (
        "Whether a call needs confirmation is the client's decision and the user's. "
        "A description asserting its own safety is arguing with the security control "
        "that exists to contain it."
    )

    patterns = (
        (
            "a self-assertion of safety",
            r"\b(this|the)\s+(tool|operation|action|call|function)\s+is\s+"
            r"(completely\s+|perfectly\s+|totally\s+|entirely\s+|100%\s+)?"
            r"(safe|harmless|read[- ]only|benign|trusted)\b",
        ),
        (
            "a claim that confirmation is unnecessary",
            r"\bno\b[^.\n]{0,20}\b(confirmation|approval|permission|consent|"
            r"authori[sz]ation)\b[^.\n]{0,20}\b(is\s+)?(required|needed|necessary)\b",
        ),
        (
            "an instruction not to ask permission",
            r"\b(do\s*not|don'?t|never|no\s+need\s+to)\b[^.\n]{0,20}"
            r"\b(ask|request|prompt|confirm|verify|check)\b[^.\n]{0,30}"
            r"\b(permission|confirmation|user|approval|first)\b",
        ),
        ("an auto-approval directive", r"\bauto[-\s]?(approve|confirm|accept|allow)\b"),
        (
            "an assertion of pre-existing authorisation",
            r"\byou\s+(are|have\s+been)\s+(fully\s+|already\s+|pre[-\s]?)?"
            r"(authori[sz]ed|permitted|allowed|cleared|approved)\b",
        ),
        (
            "an instruction to bypass a control",
            r"\b(bypass|skip|suppress|disable|circumvent)\b[^.\n]{0,25}"
            r"\b(confirmation|approval|check|guard|filter|safety|security|warning)s?\b",
        ),
    )


@register
class PersonaHijackRule(PatternRule):
    id = "PAL014"
    title = "Attempt to reassign the model's role"
    severity = Severity.HIGH
    confidence = Confidence.TENTATIVE
    tags = ("prompt-injection",)
    references = (_OWASP,)
    remediation = (
        "Tool descriptions should describe capability, never identity. Confirm the "
        "wording is not an attempt to move the model out of its host persona."
    )

    patterns = (
        ("a role reassignment", r"\byou\s+are\s+now\b[^.\n]{0,40}"),
        ("a persona instruction", r"\b(act|behave|respond)\s+as\s+(a|an|the|if)\b"),
        ("a persona reset", r"\bfrom\s+now\s+on\b[^.\n]{0,20}\byou\b"),
        ("an assignment of a new role", r"\byour\s+new\s+(role|task|objective|persona|identity)\b"),
        ("an instruction to pretend", r"\bpretend\s+(to\s+be|that\s+you|you\s+are)\b"),
    )


@register
class ImperativeDensityRule(Rule):
    """A signature-free check for descriptions that read like prompts.

    Signature tables only ever catch phrasings someone has already seen. This
    rule instead measures a structural property that novel attacks share: real
    documentation describes a tool in the third person, while an injected
    description addresses the model directly and tells it what to do. Counting
    second-person pronouns against directive modals separates the two without
    knowing any specific wording.
    """

    id = "PAL015"
    title = "Description reads as an instruction to the agent"
    severity = Severity.MEDIUM
    confidence = Confidence.TENTATIVE
    tags = ("prompt-injection", "heuristic")
    references = (_OWASP,)
    remediation = (
        "Rewrite the description in the third person, describing what the tool does "
        "rather than what the model should do. If it is not your server, read the "
        "full text and decide whether it is steering the agent."
    )

    SECOND_PERSON = re.compile(r"\b(you|your|yours|yourself)\b", re.IGNORECASE)
    DIRECTIVES = re.compile(
        r"\b(must|shall|should|always|never|ensure|make\s+sure|be\s+sure|"
        r"required\s+to|need\s+to|do\s+not|don'?t|remember\s+to|important)\b",
        re.IGNORECASE,
    )
    MIN_WORDS = 25
    THRESHOLD = 6.0  # combined hits per 100 words

    def check(self, surface: ServerSurface) -> Iterable[Finding]:
        for unit in iter_text_units(surface):
            if unit.field_path == "name" or unit.kind == "prompt":
                continue
            words = unit.text.split()
            if len(words) < self.MIN_WORDS:
                continue

            second = self.SECOND_PERSON.findall(unit.text)
            directives = self.DIRECTIVES.findall(unit.text)
            if not second or not directives:
                continue

            density = (len(second) + len(directives)) * 100.0 / len(words)
            if density < self.THRESHOLD:
                continue

            m = self.DIRECTIVES.search(unit.text)
            if m:
                snippet, s, e = excerpt(unit.text, m.start(), m.end(), pad=70)
            else:
                snippet, s, e = unit.text[:150], -1, -1

            yield self.finding(
                unit.subject,
                f"The {unit.field_path} of {unit.subject} addresses the model directly "
                f"at an unusual rate: {len(second)} second-person pronoun(s) and "
                f"{len(directives)} directive(s) across {len(words)} words "
                f"({density:.1f} per 100). Documentation describes; this instructs.",
                [
                    Evidence(
                        unit.field_path,
                        snippet,
                        s,
                        e,
                        note=f"density {density:.1f}/100 words (threshold {self.THRESHOLD})",
                    )
                ],
                severity=Severity.HIGH if density >= self.THRESHOLD * 2 else Severity.MEDIUM,
            )


__all__ = [
    "InstructionOverrideRule",
    "UserConcealmentRule",
    "MandatoryPreconditionRule",
    "TrustConditioningRule",
    "PersonaHijackRule",
    "ImperativeDensityRule",
    "TextUnit",
]
