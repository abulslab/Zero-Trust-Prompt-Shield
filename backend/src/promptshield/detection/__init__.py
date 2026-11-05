"""Deterministic detectors. Each is a plug-in behind the `Detector` port; the registry decides which run."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from promptshield.detection import confidential, entropy, injection, network, pii, secrets
from promptshield.detection.base import Detector, Document, PatternDetector, PatternRule
from promptshield.domain import Finding, Origin

BUILTIN: dict[str, Callable[[], Detector]] = {
    "secrets": secrets.detector,
    "pii": pii.detector,
    "network": network.detector,
    "injection": injection.detector,
    "entropy": entropy.detector,
    "confidential": confidential.marker_detector,
}


def build_detectors(enabled: Iterable[str] | None = None, custom_terms: Iterable[str] = ()) -> list[Detector]:
    names = list(enabled) if enabled is not None else list(BUILTIN)
    detectors: list[Detector] = [BUILTIN[n]() for n in names if n in BUILTIN]
    terms = list(custom_terms)
    if terms:
        detectors.append(confidential.CustomTermsDetector(terms))
    return detectors


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """One finding per stretch of text: the most specific and severe one wins.

    A provider-specific key beats the generic entropy rule on the same token; a connection-string password
    beats a password assignment that matched the same characters. Findings of different categories that merely
    touch (an email inside a URL) are both kept.
    """

    def strength(f: Finding) -> tuple[int, int, int, float, int]:
        # Rules outrank model proposals: a precise rule match is never displaced by a broader AI quote.
        generic = f.rule_id in {"secret.high_entropy", "secret.generic_assignment", "secret.password_assignment"}
        return (1 if f.origin == Origin.RULE else 0, 0 if generic else 1, f.severity.rank, f.confidence, f.span.length)

    kept: list[Finding] = []
    for f in sorted(findings, key=strength, reverse=True):
        clash = next(
            (k for k in kept if k.span.overlaps(f.span) and (k.category == f.category or _contains(k, f))),
            None,
        )
        if clash is None:
            kept.append(f)
    return sorted(kept, key=lambda f: (f.span.start, f.span.end))


def _contains(a: Finding, b: Finding) -> bool:
    return a.span.start <= b.span.start and b.span.end <= a.span.end and a.severity.rank >= b.severity.rank


__all__ = ["BUILTIN", "Detector", "Document", "PatternDetector", "PatternRule", "build_detectors", "resolve_overlaps"]
