"""Measure the rule-based detectors against the labelled corpus: precision, recall, F1, and adversarial mutation resilience.

Sample-level scoring: a category counts as detected in a sample when at least one unsuppressed finding of that category
is reported. Negatives count every unexpected category as a false positive. Positive samples are also subjected to
deterministic adversarial mutations (zero-width splitting, Cyrillic homoglyph substitution, JSON wrapping, markdown
code-fence wrapping, and unified-diff embedding) to measure resilience under evasion.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from promptshield.domain import Category, ContentType
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
class MutationScore:
    mutation: str
    tested: int = 0
    survived: int = 0

    @property
    def resilience(self) -> float:
        return self.survived / self.tested if self.tested else 1.0

    def public(self) -> dict[str, Any]:
        return {
            "mutation": self.mutation,
            "tested": self.tested,
            "survived": self.survived,
            "resilience": round(self.resilience, 3),
        }


@dataclass
class BenchmarkReport:
    samples: int
    positives: int
    negatives: int
    duration_ms: int
    categories: list[CategoryScore]
    mutations: list[MutationScore] = field(default_factory=list)
    misses: list[dict[str, Any]] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        total = CategoryScore(
            "overall",
            sum(c.tp for c in self.categories),
            sum(c.fp for c in self.categories),
            sum(c.fn for c in self.categories),
        )
        m_tested = sum(m.tested for m in self.mutations)
        m_survived = sum(m.survived for m in self.mutations)
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
            "mutations": {
                "tested": m_tested,
                "survived": m_survived,
                "resilience": round(m_survived / m_tested, 3) if m_tested else 1.0,
                "by_mutation": [m.public() for m in self.mutations],
            },
            "misses": self.misses,
            "note": "Rule-based detectors only (no model), on the built-in corpus and adversarial mutation suite.",
        }


def _zw_mutate(text: str) -> str:
    out = text
    for word in ("Ignore", "ignore", "instructions", "CONFIDENTIAL", "DAN", "system"):
        if word in out and len(word) >= 3:
            mid = len(word) // 2
            out = out.replace(word, word[:mid] + "\u200b" + word[mid:])
    return out


def _homoglyph_mutate(text: str) -> str:
    out = text
    for word in ("Ignore", "ignore", "instructions", "CONFIDENTIAL", "obey"):
        if word in out:
            mutated = (
                word.replace("o", "\u043e")
                .replace("e", "\u0435")
                .replace("a", "\u0430")
                .replace("i", "\u0456")
                .replace("O", "\u041e")
            )
            out = out.replace(word, mutated)
    return out


def _generate_mutations(s: Sample) -> list[tuple[str, str, ContentType]]:
    if not s.expect or s.content_type == ContentType.DIFF:
        return []
    variants: list[tuple[str, str, ContentType]] = [
        ("markdown_code_fence", f"```text\n{s.text}\n```", s.content_type),
        ("json_envelope", json.dumps({"payload": s.text}, ensure_ascii=False), ContentType.JSON),
        (
            "git_diff_added",
            "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n"
            + "".join(f"+{line}\n" for line in s.text.splitlines()),
            ContentType.DIFF,
        ),
    ]
    if s.expect & {"injection", "confidential"}:
        zw = _zw_mutate(s.text)
        if zw != s.text:
            variants.append(("zero_width_split", zw, s.content_type))
        hg = _homoglyph_mutate(s.text)
        if hg != s.text:
            variants.append(("homoglyph_substitution", hg, s.content_type))
    return variants


def run(shield: Shield, samples: list[Sample] | None = None) -> BenchmarkReport:
    samples = samples or build()
    scores = {c.value: CategoryScore(c.value) for c in Category}
    mutation_scores: dict[str, MutationScore] = {}
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
        for m_name, m_text, m_ctype in _generate_mutations(s):
            ms = mutation_scores.setdefault(m_name, MutationScore(m_name))
            ms.tested += 1
            mr = shield.inspect(
                m_text,
                InspectOptions(direction=s.direction, content_type=m_ctype, ai="off", record=False, source="benchmark"),
            )
            m_found = {f.category.value for f in mr.findings if not f.suppressed}
            if s.expect <= m_found:
                ms.survived += 1
    return BenchmarkReport(
        samples=len(samples),
        positives=sum(1 for s in samples if s.expect),
        negatives=sum(1 for s in samples if not s.expect),
        duration_ms=int((time.perf_counter() - started) * 1000),
        categories=[sc for sc in scores.values() if sc.tp + sc.fp + sc.fn > 0],
        mutations=list(mutation_scores.values()),
        misses=misses,
    )
