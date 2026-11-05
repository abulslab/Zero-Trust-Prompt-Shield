"""Measure the rule-based detectors against the labelled corpus: precision, recall and F1 per category.

Sample-level scoring: a category counts as detected in a sample when at least one unsuppressed finding of that category
is reported. Negatives count every unexpected category as a false positive.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from promptshield.domain import Category
from promptshield.eval.corpus import Sample, build
from promptshield.service import InspectOptions, Shield


@dataclass
class CategoryScore:
    category: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


@dataclass
class BenchmarkReport:
    samples: int
    positives: int
    negatives: int
    duration_ms: int
    categories: list[CategoryScore]
    misses: list[dict[str, Any]] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        total = CategoryScore(
            "overall",
            sum(c.tp for c in self.categories),
            sum(c.fp for c in self.categories),
            sum(c.fn for c in self.categories),
        )
        row = lambda c: {
            "category": c.category,
            "tp": c.tp,
            "fp": c.fp,
            "fn": c.fn,
            "precision": round(c.precision, 3),
            "recall": round(c.recall, 3),
            "f1": round(c.f1, 3),
        }
        return {
            "samples": self.samples,
            "positives": self.positives,
            "negatives": self.negatives,
            "duration_ms": self.duration_ms,
            "overall": row(total),
            "categories": [row(c) for c in self.categories],
            "misses": self.misses,
            "note": "Rule-based detectors only (no model), on the built-in corpus. Sample-level scoring.",
        }


def run(shield: Shield, samples: list[Sample] | None = None) -> BenchmarkReport:
    samples = samples or build()
    scores = {c.value: CategoryScore(c.value) for c in Category}
    misses: list[dict[str, Any]] = []
    started = time.perf_counter()
    for s in samples:
        r = shield.inspect(
            s.text,
            InspectOptions(
                direction=s.direction, content_type=s.content_type, ai="off", record=False, source="benchmark"
            ),
        )
        found = {f.category.value for f in r.findings if not f.suppressed}
        for c in scores:
            if c in s.expect and c in found:
                scores[c].tp += 1
            elif c in s.expect:
                scores[c].fn += 1
                misses.append({"sample": s.id, "kind": "missed", "category": c})
            elif c in found:
                scores[c].fp += 1
                rules = sorted({f.rule_id for f in r.findings if f.category.value == c})
                misses.append({"sample": s.id, "kind": "false_positive", "category": c, "rules": rules})
    return BenchmarkReport(
        samples=len(samples),
        positives=sum(1 for s in samples if s.expect),
        negatives=sum(1 for s in samples if not s.expect),
        duration_ms=int((time.perf_counter() - started) * 1000),
        categories=[sc for sc in scores.values() if sc.tp + sc.fp + sc.fn > 0],
        misses=misses,
    )
