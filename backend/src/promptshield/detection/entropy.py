"""Unknown secrets: long random-looking tokens that no provider-specific rule recognised.

Kept deliberately conservative. Hex hashes, UUIDs and ordinary identifiers are random-looking too, so they are
excluded, and a token only counts when it mixes character classes the way generated keys do.
"""

from __future__ import annotations

import re

from promptshield.detection.base import Document
from promptshield.detection.validators import shannon_entropy
from promptshield.domain import Category, Finding, Origin, Severity

_TOKEN = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{24,}(?![A-Za-z0-9_+/=-])")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_KEYWORD_NEAR = re.compile(r"(?i)(?:key|token|secret|passw|credential|auth|signature|sig)\w*\s*[\"']?\s*[:=]")


class EntropyDetector:
    name = "entropy"

    def __init__(self, threshold: float = 4.3) -> None:
        self.threshold = threshold

    def detect(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        for m in _TOKEN.finditer(doc.text):
            token = m.group(0).strip("=-_")
            if len(token) < 24 or _UUID.match(token) or _HEX.match(token):
                continue
            classes = sum(bool(re.search(p, token)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
            if classes < 3 or ("/" in token and token.count("/") > 2):  # paths and URLs
                continue
            score = shannon_entropy(token)
            if score < self.threshold:
                continue
            if not doc.in_scope(*m.span()):
                continue
            near_keyword = bool(_KEYWORD_NEAR.search(doc.text[max(0, m.start() - 40) : m.start()]))
            findings.append(
                Finding(
                    rule_id="secret.high_entropy",
                    detector=self.name,
                    category=Category.SECRET,
                    severity=Severity.HIGH if near_keyword else Severity.MEDIUM,
                    confidence=min(0.9, 0.45 + (score - self.threshold) * 0.3 + (0.25 if near_keyword else 0.0)),
                    title="Random-looking token",
                    message=f"A {len(token)}-character token with entropy {score:.2f} bits/char looks like a generated key.",
                    guidance="If this is a credential, remove and rotate it. If it is an identifier, mark it as not a secret so it is suppressed next time.",
                    span=doc.span(*m.span()),
                    origin=Origin.RULE,
                    tags=["credential"],
                    value=m.group(0),
                )
            )
        return findings


def detector() -> EntropyDetector:
    return EntropyDetector()
