"""Domain model shared by every layer: findings, spans, decisions and results.

Nothing here knows about HTTP, storage or models. Raw sensitive values never leave this layer
except through `Finding.value`, which is excluded from every serialised form.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def weight(self) -> float:
        """Contribution of one finding of this severity to the risk score (before confidence)."""
        return _SEVERITY_WEIGHT[self]


_SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
_SEVERITY_WEIGHT = {
    Severity.INFO: 0.02,
    Severity.LOW: 0.10,
    Severity.MEDIUM: 0.30,
    Severity.HIGH: 0.60,
    Severity.CRITICAL: 0.90,
}


class Category(StrEnum):
    SECRET = "secret"  # credentials, keys, tokens, private keys
    PII = "pii"  # personal data
    FINANCIAL = "financial"  # card numbers, IBANs
    NETWORK = "network"  # internal addresses, hosts, URLs
    INJECTION = "injection"  # prompt injection / jailbreak attempts
    OBFUSCATION = "obfuscation"  # hidden characters, encoded payloads
    EXFILTRATION = "exfiltration"  # channels that would leak data out (markdown image beacons, ...)
    CONFIDENTIAL = "confidential"  # confidentiality markers, custom terms, organisational context


class Direction(StrEnum):
    """Where the text sits relative to the model. The same pattern means different things in each."""

    INPUT = "input"  # a prompt a person or system is about to send
    CONTEXT = "context"  # retrieved documents, tool output, web pages: untrusted data entering the context
    OUTPUT = "output"  # what a model answered


class ContentType(StrEnum):
    TEXT = "text"
    PROMPT = "prompt"
    CODE = "code"
    DIFF = "diff"
    JSON = "json"


class Origin(StrEnum):
    RULE = "rule"  # deterministic detector
    MODEL = "model"  # proposed by a model and verified by the engine


class Action(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return {"allow": 0, "warn": 1, "redact": 2, "block": 3}[self.value]


class Span(BaseModel):
    model_config = ConfigDict(frozen=True)

    start: int
    end: int
    line: int = 1
    column: int = 1

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end

    @property
    def length(self) -> int:
        return self.end - self.start


def mask(value: str, category: Category | None = None) -> str:
    """A preview that identifies a value to its owner without disclosing it."""
    v = value.strip()
    if not v:
        return ""
    if category == Category.PII and "@" in v:
        local, _, domain = v.partition("@")
        return f"{local[:1]}***@{domain}"
    if len(v) <= 6:
        return "*" * len(v)
    keep = 4 if len(v) >= 16 else 2
    return f"{v[:keep]}{'*' * min(8, len(v) - keep)}"


_fingerprint_key: bytes | None = None


def set_fingerprint_key(key: str | None) -> None:
    """Configure an optional HMAC key for finding fingerprints."""
    global _fingerprint_key
    _fingerprint_key = key.encode("utf-8") if key else None


def fingerprint(rule_id: str, value: str, key: str | None = None) -> str:
    """Stable identity of a finding across inspections, without storing the value itself.

    Uses HMAC-SHA256 when `key` or `SHIELD_FINGERPRINT_KEY` is configured so low-entropy values
    (phone numbers, SSNs, internal IPs) cannot be reversed by rainbow tables.
    """
    payload = f"{rule_id}\x00{value.strip()}".encode()
    effective_key = (
        key.encode("utf-8")
        if key
        else (_fingerprint_key or os.environ.get("SHIELD_FINGERPRINT_KEY", "").encode("utf-8") or None)
    )
    if effective_key:
        return hmac.new(effective_key, payload, hashlib.sha256).hexdigest()[:24]
    return hashlib.sha256(payload).hexdigest()[:24]


class Finding(BaseModel):
    """One verified problem in the text. `value` is the raw match and is never serialised."""

    rule_id: str
    detector: str
    category: Category
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    message: str
    guidance: str
    span: Span
    origin: Origin = Origin.RULE
    tags: list[str] = Field(default_factory=list)
    value: str = Field(default="", exclude=True, repr=False)
    suppressed: bool = False
    action: Action = Action.ALLOW  # set by the policy engine

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.rule_id, self.value)

    @property
    def score(self) -> float:
        return self.severity.weight * self.confidence

    def public(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["id"] = self.fingerprint
        data["preview"] = mask(self.value, self.category)
        data["placeholder_label"] = self.rule_id.split(".")[-1].upper()
        return data


class Rejection(BaseModel):
    """A model proposal the verifier refused, with the reason. Kept so people can see what AI got wrong."""

    category: str
    reason: str
    evidence_preview: str = ""


class AiReport(BaseModel):
    requested: bool = False
    used: bool = False
    provider: str | None = None
    model: str | None = None
    proposed: int = 0
    verified: int = 0
    rejections: list[Rejection] = Field(default_factory=list)
    error: str | None = None
    latency_ms: int | None = None


class Decision(BaseModel):
    action: Action
    risk_score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    policy_id: str


class InspectionResult(BaseModel):
    id: str
    created_at: str
    direction: Direction
    content_type: ContentType
    length: int
    content_sha256: str
    decision: Decision
    findings: list[Finding]
    summary: str
    redacted: str | None = None
    ai: AiReport = Field(default_factory=AiReport)
    timings_ms: dict[str, int] = Field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        data = self.model_dump(mode="json", exclude={"findings"})
        data["findings"] = [f.public() for f in self.findings]
        data["counts"] = counts_by_category(self.findings)
        return data


def counts_by_category(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        if not f.suppressed:
            out[f.category.value] = out.get(f.category.value, 0) + 1
    return out
