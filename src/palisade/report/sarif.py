"""SARIF 2.1.0 output.

SARIF is what lets a scan result show up in GitHub code scanning and most CI
security dashboards, which is the difference between a tool someone runs once
and a tool that stays in a pipeline.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from palisade import __version__
from palisade.models import Finding, ScanReport, Severity
from palisade.rules import all_rules

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# SARIF security-severity is a CVSS-like number that GitHub uses for bucketing.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule_metadata() -> list[dict[str, Any]]:
    out = []
    for rule in all_rules():
        out.append(
            {
                "id": rule.id,
                "name": rule.__class__.__name__,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": (rule.__doc__ or rule.title).strip()},
                "help": {"text": rule.remediation or rule.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": list(rule.tags),
                    "security-severity": _SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    return out


def _result(finding: Finding, artifact_uri: str) -> dict[str, Any]:
    locations = []
    for ev in finding.evidence[:1]:
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"snippet": {"text": ev.snippet[:1000]}},
                },
                "logicalLocations": [
                    {
                        "name": finding.subject,
                        "fullyQualifiedName": f"{finding.subject}.{ev.field_path}",
                    }
                ],
            }
        )
    if not locations:
        locations.append({"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}})

    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}: {finding.description}"},
        "locations": locations,
        "partialFingerprints": {"palisadeFingerprint/v1": finding.fingerprint},
        "properties": {
            "confidence": finding.confidence.value,
            "severity": finding.severity.value,
            "subject": finding.subject,
            "tags": finding.tags,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }


def build(reports: Sequence[ScanReport], extra: Sequence[Finding] = ()) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for report in reports:
        uri = report.surface.origin or f"mcp://{report.surface.server_id}"
        results.extend(_result(f, uri) for f in report.sorted_findings())
    for finding in extra:
        results.append(_result(finding, "mcp://workspace"))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Palisade",
                        "version": __version__,
                        "informationUri": "https://github.com/divyansh/mcp-palisade",
                        "rules": _rule_metadata(),
                    }
                },
                "results": results,
            }
        ],
    }
