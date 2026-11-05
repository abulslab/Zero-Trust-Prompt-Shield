"""Confidentiality markers and organisation-specific terms (code names, customers, internal systems).

Custom terms come from the active policy pack, so each organisation teaches the shield its own vocabulary
without code changes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from promptshield.detection.base import Document, PatternDetector, PatternRule
from promptshield.domain import Category, Finding, Origin, Severity

MARKERS = PatternRule(
    id="confidential.marker",
    category=Category.CONFIDENTIAL,
    severity=Severity.MEDIUM,
    title="Confidentiality marking",
    message="The text is labelled as restricted. Its owner did not intend it to leave the organisation.",
    guidance="Check the document's classification allows sharing with this model; if not, summarise it without the restricted parts.",
    pattern=r"(?i)\b(?:strictly\s+confidential|confidential|internal\s+(?:use\s+)?only|company\s+confidential|proprietary(?:\s+and\s+confidential)?|do\s+not\s+(?:distribute|share|forward)|not\s+for\s+(?:external\s+)?distribution|under\s+NDA|trade\s+secret|restricted\s+distribution)\b",
    confidence=0.8,
    tags=("classification",),
)


class CustomTermsDetector:
    """Exact, case-insensitive whole-word matches for terms an organisation registers in its policy."""

    name = "custom_terms"

    def __init__(self, terms: Iterable[str], severity: Severity = Severity.HIGH) -> None:
        cleaned = sorted({t.strip() for t in terms if t and t.strip()}, key=len, reverse=True)
        self.severity = severity
        self._pattern = (
            re.compile(r"(?i)(?<!\w)(?:" + "|".join(re.escape(t) for t in cleaned) + r")(?!\w)") if cleaned else None
        )

    def detect(self, doc: Document) -> list[Finding]:
        if self._pattern is None:
            return []
        findings: list[Finding] = []
        for m in self._pattern.finditer(doc.text):
            if not doc.in_scope(*m.span()):
                continue
            findings.append(
                Finding(
                    rule_id="confidential.custom_term",
                    detector=self.name,
                    category=Category.CONFIDENTIAL,
                    severity=self.severity,
                    confidence=0.95,
                    title="Restricted term",
                    message="A term your organisation registered as restricted (code name, customer, internal system).",
                    guidance="Replace it with a neutral label; the policy lists it because it should not reach external models.",
                    span=doc.span(*m.span()),
                    origin=Origin.RULE,
                    tags=["policy"],
                    value=m.group(0),
                )
            )
        return findings


def marker_detector() -> PatternDetector:
    return PatternDetector("confidential", [MARKERS])
