"""Rule execution.

The engine owns three concerns that individual rules should not: which rules
run, which findings survive filtering, and how a rule that raises is prevented
from taking the whole scan down with it.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from palisade.models import Confidence, Finding, ScanReport, ServerSurface, Severity
from palisade.rules import CrossServerRule, Rule, all_rules


@dataclass
class Baseline:
    """A set of fingerprints a team has already triaged and accepted."""

    fingerprints: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | None) -> Baseline:
        if not path or not os.path.exists(path):
            return cls()
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return cls(set(data))
        return cls(set(data.get("fingerprints", [])))

    @classmethod
    def from_report(cls, report: ScanReport) -> Baseline:
        return cls({f.fingerprint for f in report.findings})

    def save(self, path: str) -> None:
        payload = {
            "_comment": (
                "Fingerprints of findings accepted by a reviewer. Delete an entry to "
                "surface that finding again."
            ),
            "fingerprints": sorted(self.fingerprints),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")

    def suppresses(self, finding: Finding) -> bool:
        return finding.fingerprint in self.fingerprints


@dataclass
class Engine:
    rules: list[Rule] = field(default_factory=all_rules)
    baseline: Baseline = field(default_factory=Baseline)
    min_severity: Severity = Severity.INFO
    disabled: frozenset[str] = frozenset()

    def active_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.id not in self.disabled]

    def _keep(self, finding: Finding) -> bool:
        if finding.severity.rank < self.min_severity.rank:
            return False
        return not self.baseline.suppresses(finding)

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Apply this engine's severity floor and baseline to findings it didn't produce.

        Lets a caller run findings from outside the rule registry -- the
        semantic judge, say -- through the same min-severity and baseline
        policy as everything else, rather than reimplementing it.
        """
        return [f for f in findings if self._keep(f)]

    def _run(self, rule: Rule, surface: ServerSurface) -> Iterable[Finding]:
        try:
            yield from rule.check(surface)
        except Exception as exc:  # a broken rule must not abort the scan
            yield Finding(
                rule_id="PAL999",
                title="Rule raised an exception",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                subject=f"rule: {rule.id}",
                description=f"{rule.id} failed on this surface: {exc!r}",
                remediation="Report this as a Palisade bug with the offending surface.",
            )

    def scan(self, surface: ServerSurface) -> ScanReport:
        rules = self.active_rules()
        findings: list[Finding] = []
        for rule in rules:
            for finding in self._run(rule, surface):
                if self._keep(finding):
                    findings.append(finding)
        return ScanReport(surface=surface, findings=findings, rules_run=len(rules))

    def scan_workspace(
        self, surfaces: Sequence[ServerSurface]
    ) -> tuple[list[ScanReport], list[Finding]]:
        """Scan each server, then run cross-server rules over the whole set.

        Returned separately because a collision between two servers belongs to
        neither of them.
        """
        reports = [self.scan(s) for s in surfaces]

        cross: list[Finding] = []
        for rule in self.active_rules():
            if not isinstance(rule, CrossServerRule):
                continue
            try:
                for finding in rule.check_many(surfaces):
                    if self._keep(finding):
                        cross.append(finding)
            except Exception:
                continue
        return reports, cross
