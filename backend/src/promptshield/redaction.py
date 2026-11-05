"""Redaction and restoration.

`placeholder` mode is reversible: each distinct value gets a stable label (<<EMAIL_1>>) and the mapping is handed to
the caller, never stored. `synthetic` mode is also reversible and replaces common entities (emails, phones, IPs, hosts,
cards) with RFC-reserved format-preserving surrogates (`user1@redacted.invalid`, `192.0.2.1`) so downstream parsers and
models see natural syntax. `mask` mode is one-way ([REDACTED:EMAIL]) for logs and sharing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from promptshield.domain import Finding


class RedactionMode(StrEnum):
    PLACEHOLDER = "placeholder"
    MASK = "mask"
    SYNTHETIC = "synthetic"


@dataclass(frozen=True)
class Segment:
    """A replaced stretch: where it sits in the original text and in the redacted text."""

    orig_start: int
    orig_end: int
    red_start: int
    red_end: int
    label: str


@dataclass
class Redaction:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)  # placeholder or surrogate -> original value
    segments: list[Segment] = field(default_factory=list)

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """Map a span of the redacted text back to the original text. A span touching a label covers the whole value."""
        return self._map(start, is_end=False), self._map(end, is_end=True)

    def _map(self, pos: int, *, is_end: bool) -> int:
        shift = 0
        for s in self.segments:
            if pos <= s.red_start if is_end else pos < s.red_start:
                break
            if pos < s.red_end or (is_end and pos == s.red_end):
                return s.orig_end if is_end else s.orig_start
            shift = s.orig_end - s.red_end
        return pos + shift


def label_for(f: Finding) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", f.rule_id.split(".")[-1].upper()).strip("_") or "VALUE"


def _synthetic_token(label: str, index: int) -> str:
    if label == "EMAIL":
        return f"user{index}@redacted.invalid"
    if label == "PHONE":
        return f"+44 20 7946 {index:04d}"
    if label == "SSN":
        return f"000-00-{index:04d}"
    if label == "PRIVATE_IP":
        return f"192.0.2.{min(index, 254)}"
    if label == "INTERNAL_HOST":
        return f"host{index}.redacted.invalid"
    if label == "INTERNAL_URL":
        return f"https://host{index}.redacted.invalid/resource"
    if label == "CARD_NUMBER":
        return f"4000 0000 0000 {index:04d}"
    if label == "IBAN":
        return f"GB00REDACTED{index:010d}"
    return f"<<{label}_{index}>>"


_SYNTH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"user(\d+)@redacted\.invalid")),
    ("PHONE", re.compile(r"\+44 20 7946 (\d{4})")),
    ("SSN", re.compile(r"000-00-(\d{4})")),
    ("PRIVATE_IP", re.compile(r"192\.0\.2\.(\d+)")),
    ("INTERNAL_HOST", re.compile(r"host(\d+)\.redacted\.invalid")),
    ("INTERNAL_URL", re.compile(r"https://host(\d+)\.redacted\.invalid/resource")),
    ("CARD_NUMBER", re.compile(r"4000 0000 0000 (\d{4})")),
    ("IBAN", re.compile(r"GB00REDACTED(\d{10})")),
]


def redact(
    text: str,
    findings: list[Finding],
    mode: RedactionMode = RedactionMode.PLACEHOLDER,
    shared: dict[str, str] | None = None,
) -> Redaction:
    """Replace each finding's span. Pass `shared` to keep labels consistent across several texts (chat messages)."""
    chosen = sorted((f for f in findings if not f.suppressed), key=lambda f: (f.span.start, -f.span.end))
    out: list[str] = []
    result = Redaction(text="", mapping=shared if shared is not None else {})
    by_value: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    for placeholder, val in result.mapping.items():
        m = _LABEL.fullmatch(placeholder)
        if m:
            label, _, n = m.group(1).rpartition("_")
            by_value[(label, val)] = placeholder
            counters[label] = max(counters.get(label, 0), int(n))
            continue
        for syn_label, syn_re in _SYNTH_PATTERNS:
            sm = syn_re.fullmatch(placeholder)
            if sm:
                by_value[(syn_label, val)] = placeholder
                counters[syn_label] = max(counters.get(syn_label, 0), int(sm.group(1)))
                break
    cursor = 0
    red_len = 0
    for f in chosen:
        if f.span.start < cursor:  # nested or overlapping: the outer one already covers it
            continue
        label = label_for(f)
        if mode == RedactionMode.MASK:
            token = f"[REDACTED:{label}]"
        else:
            key = (label, f.value)
            if key not in by_value:
                counters[label] = counters.get(label, 0) + 1
                token_str = (
                    _synthetic_token(label, counters[label])
                    if mode == RedactionMode.SYNTHETIC
                    else f"<<{label}_{counters[label]}>>"
                )
                by_value[key] = token_str
                result.mapping[token_str] = f.value
            token = by_value[key]
        chunk = text[cursor : f.span.start]
        out.append(chunk)
        red_len += len(chunk)
        result.segments.append(Segment(f.span.start, f.span.end, red_len, red_len + len(token), label))
        out.append(token)
        red_len += len(token)
        cursor = f.span.end
    out.append(text[cursor:])
    result.text = "".join(out)
    return result


_LABEL = re.compile(r"<<\s*([A-Z0-9_]+_\d+)\s*>>")


def restore(text: str, mapping: dict[str, str]) -> tuple[str, list[str]]:
    """Put original values back. Tolerates models that add spaces inside brackets and restores synthetic surrogates."""
    unknown: list[str] = []

    def sub(m: re.Match[str]) -> str:
        key = f"<<{m.group(1)}>>"
        if key in mapping:
            return mapping[key]
        unknown.append(key)
        return m.group(0)

    restored = _LABEL.sub(sub, text)
    # Also restore format-preserving synthetic surrogates (ordered longest-first so user10 precedes user1).
    synthetic_keys = sorted((k for k in mapping if not _LABEL.fullmatch(k)), key=len, reverse=True)
    for key in synthetic_keys:
        if key in restored:
            restored = restored.replace(key, mapping[key])
    return restored, unknown
