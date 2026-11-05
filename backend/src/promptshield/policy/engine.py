"""Policy as code: YAML packs decide what each finding means for this organisation.

A pack lists which detectors run, the organisation's restricted terms, and ordered rules. Each finding takes the
action of the first rule it matches; the decision is the most restrictive action over all findings, raised to
"block" when the overall risk score reaches the pack's threshold.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from promptshield.domain import Action, Category, Decision, Direction, Finding, Severity

BUILTIN_DIR = Path(__file__).parent / "packs"


class Match(BaseModel):
    category: list[Category] | None = None
    direction: list[Direction] | None = None
    rule: list[str] | None = None  # rule-id prefixes, e.g. "secret.high_entropy" or "ai."
    min_severity: Severity | None = None
    min_confidence: float | None = None
    origin: Literal["rule", "model"] | None = None

    @field_validator("category", "direction", "rule", mode="before")
    @classmethod
    def _listify(cls, v: object) -> object:
        return [v] if isinstance(v, str) else v

    def matches(self, f: Finding, direction: Direction) -> bool:
        if self.category and f.category not in self.category:
            return False
        if self.direction and direction not in self.direction:
            return False
        if self.rule and not any(f.rule_id.startswith(p) for p in self.rule):
            return False
        if self.min_severity and f.severity.rank < self.min_severity.rank:
            return False
        if self.min_confidence is not None and f.confidence < self.min_confidence:
            return False
        return not (self.origin and f.origin.value != self.origin)


class PolicyRule(BaseModel):
    when: Match = Field(default_factory=Match)
    action: Action
    reason: str | None = None


class Policy(BaseModel):
    id: str
    name: str
    description: str = ""
    detectors: list[str] = Field(
        default_factory=lambda: ["secrets", "pii", "network", "injection", "entropy", "confidential"]
    )
    custom_terms: list[str] = Field(default_factory=list)
    ai_review: Literal["off", "auto", "on"] = "auto"
    block_score: int = 90
    default_action: Action = Action.ALLOW
    rules: list[PolicyRule] = Field(default_factory=list)
    builtin: bool = True

    def action_for(self, f: Finding, direction: Direction) -> tuple[Action, str | None]:
        for r in self.rules:
            if r.when.matches(f, direction):
                return r.action, r.reason
        return self.default_action, None

    def decide(self, findings: list[Finding], direction: Direction) -> Decision:
        active = [f for f in findings if not f.suppressed]
        score = risk_score(active)
        action = Action.ALLOW
        reasons: list[str] = []
        for f in active:
            a, why = self.action_for(f, direction)
            if f.action.rank > a.rank:
                a = f.action
                why = why or f.title
            f.action = a
            if a.rank > action.rank:
                action = a
            if a in (Action.BLOCK, Action.REDACT) and why and why not in reasons:
                reasons.append(why)
        if score >= self.block_score and action != Action.BLOCK:
            action = Action.BLOCK
            reasons.insert(0, f"Overall risk {score} is at or above the policy's block threshold ({self.block_score}).")
        if not reasons and action != Action.ALLOW:
            reasons.append(f"{len(active)} finding(s) need attention under policy '{self.name}'.")
        return Decision(action=action, risk_score=score, reasons=reasons, policy_id=self.id)


def risk_score(findings: list[Finding]) -> int:
    """Probability-style aggregation: independent findings compound, one critical finding dominates."""
    keep = 1.0
    for f in findings:
        keep *= 1.0 - f.score
    return math.floor((1.0 - keep) * 100 + 0.5)


class PolicyStore:
    def __init__(self, extra_dir: str | None = None) -> None:
        self._policies: dict[str, Policy] = {}
        self._load(BUILTIN_DIR, builtin=True)
        if extra_dir and Path(extra_dir).is_dir():
            self._load(Path(extra_dir), builtin=False)

    def _load(self, folder: Path, *, builtin: bool) -> None:
        for path in sorted(folder.glob("*.y*ml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            data["builtin"] = builtin
            p = Policy.model_validate(data)
            self._policies[p.id] = p

    def get(self, policy_id: str) -> Policy:
        if policy_id not in self._policies:
            raise KeyError(policy_id)
        return self._policies[policy_id]

    def all(self) -> list[Policy]:
        return list(self._policies.values())
