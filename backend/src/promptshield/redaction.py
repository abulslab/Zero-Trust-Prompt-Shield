"""Redaction and restoration.

`placeholder` mode is reversible: each distinct value gets a stable label (<<EMAIL_1>>) and the mapping is handed to
the caller, never stored. Send the redacted text to a model, then restore the labels in its answer. `mask` mode is
one-way ([REDACTED:EMAIL]) for logs and sharing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from promptshield.domain import Finding


class RedactionMode(StrEnum):
    PLACEHOLDER = "placeholder"
    MASK = "mask"


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
    mapping: dict[str, str] = field(default_factory=dict)  # placeholder -> original value
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
                by_value[key] = f"<<{label}_{counters[label]}>>"
                result.mapping[by_value[key]] = f.value
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
    """Put original values back. Tolerates models that add spaces inside the brackets. Returns unknown labels."""
    unknown: list[str] = []

    def sub(m: re.Match[str]) -> str:
        key = f"<<{m.group(1)}>>"
        if key in mapping:
            return mapping[key]
        unknown.append(key)
        return m.group(0)

    return _LABEL.sub(sub, text), unknown
