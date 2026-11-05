"""Detector port and the shared document view every detector works on."""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

from promptshield.domain import Category, ContentType, Direction, Finding, Origin, Severity, Span

_CONFUSABLES: dict[str, str] = {
    # Cyrillic -> Latin homoglyphs (escaped as \uXXXX so static linters do not flag RUF001)
    "\u0430": "a",
    "\u0432": "b",
    "\u0435": "e",
    "\u0456": "i",
    "\u0457": "i",
    "\u0458": "j",
    "\u043a": "k",
    "\u043c": "m",
    "\u043d": "h",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0442": "t",
    "\u0443": "y",
    "\u0445": "x",
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u0406": "I",
    "\u0408": "J",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0423": "Y",
    "\u0425": "X",
    # Greek -> Latin homoglyphs
    "\u03b1": "a",
    "\u03b2": "b",
    "\u03b5": "e",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bd": "v",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
}


def _is_invisible(cp: int) -> bool:
    return (
        cp == 0x00AD
        or 0x200B <= cp <= 0x200F
        or 0x202A <= cp <= 0x202E
        or 0x2060 <= cp <= 0x206F
        or cp == 0xFEFF
        or 0xE0000 <= cp <= 0xE007F
    )


def _build_shadow(text: str) -> tuple[str, list[int], bool]:
    """Build a de-obfuscated shadow view and a coordinate map back to `text` indices."""
    if text.isascii():
        return text, [], False
    norm_chars: list[str] = []
    norm_to_orig: list[int] = []
    changed = False
    for idx, ch in enumerate(text):
        cp = ord(ch)
        if _is_invisible(cp):
            changed = True
            continue
        if 0xFF01 <= cp <= 0xFF5E:
            norm_chars.append(chr(cp - 0xFEE0))
            norm_to_orig.append(idx)
            changed = True
        elif ch in _CONFUSABLES:
            norm_chars.append(_CONFUSABLES[ch])
            norm_to_orig.append(idx)
            changed = True
        else:
            norm_chars.append(ch)
            norm_to_orig.append(idx)
    if not changed:
        return text, [], False
    return "".join(norm_chars), norm_to_orig, True


class Document:
    """The text under inspection plus what detectors need to know about it.

    For a diff, only added lines are in scope: removed and context lines are already in the repository
    and are not what the author is about to share.

    When invisible Unicode controls or homoglyphs are present, `normalized` holds a de-obfuscated shadow
    projection and `map_normalized_span` translates shadow coordinates back to exact spans in `text`.
    """

    def __init__(self, text: str, content_type: ContentType, direction: Direction) -> None:
        self.text = text
        self.content_type = content_type
        self.direction = direction
        self._line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
        self._scope = self._diff_scope(text) if content_type == ContentType.DIFF else None
        self.normalized, self._norm_to_orig, self.has_obfuscation = _build_shadow(text)

    def span(self, start: int, end: int) -> Span:
        line_index = bisect.bisect_right(self._line_starts, start) - 1
        return Span(start=start, end=end, line=line_index + 1, column=start - self._line_starts[line_index] + 1)

    def map_normalized_span(self, norm_start: int, norm_end: int) -> tuple[int, int]:
        if not self._norm_to_orig or norm_start >= norm_end:
            return norm_start, norm_end
        return self._norm_to_orig[norm_start], self._norm_to_orig[norm_end - 1] + 1

    def in_scope(self, start: int, end: int) -> bool:
        if self._scope is None:
            return True
        return any(s <= start and end <= e for s, e in self._scope)

    @staticmethod
    def _diff_scope(text: str) -> list[tuple[int, int]]:
        scope: list[tuple[int, int]] = []
        pos = 0
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            if body.startswith("+") and not body.startswith("+++"):
                scope.append((pos + 1, pos + len(body)))
            pos += len(line)
        return scope


class Detector(Protocol):
    name: str

    def detect(self, doc: Document) -> list[Finding]: ...


Validator = Callable[[str], bool]


@dataclass(frozen=True)
class PatternRule:
    """A declarative rule: one regular expression, the group holding the sensitive value, and what it means."""

    id: str
    category: Category
    severity: Severity
    title: str
    message: str
    guidance: str
    pattern: str
    group: str | int = 0
    confidence: float = 0.9
    flags: int = 0
    validator: Validator | None = None
    directions: frozenset[Direction] = field(default_factory=lambda: frozenset(Direction))
    severity_by_direction: dict[Direction, Severity] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    def compiled(self) -> re.Pattern[str]:
        return _compile(self.pattern, self.flags)


_cache: dict[tuple[str, int], re.Pattern[str]] = {}


def _compile(pattern: str, flags: int) -> re.Pattern[str]:
    key = (pattern, flags)
    if key not in _cache:
        _cache[key] = re.compile(pattern, flags)
    return _cache[key]


_SHADOW_CATEGORIES = frozenset({Category.INJECTION, Category.CONFIDENTIAL, Category.SECRET})


class PatternDetector:
    """Runs a set of `PatternRule`s. Most detectors are just a named rule list."""

    def __init__(self, name: str, rules: Iterable[PatternRule]) -> None:
        self.name = name
        self.rules = list(rules)

    def detect(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()
        for rule in self.rules:
            if doc.direction not in rule.directions:
                continue
            compiled = rule.compiled()
            for m in compiled.finditer(doc.text):
                start, end = m.span(rule.group)
                if start < 0 or start == end:
                    continue
                value = doc.text[start:end]
                if not doc.in_scope(start, end):
                    continue
                if rule.validator is not None and not rule.validator(value):
                    continue
                seen.add((rule.id, start, end))
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        detector=self.name,
                        category=rule.category,
                        severity=rule.severity_by_direction.get(doc.direction, rule.severity),
                        confidence=rule.confidence,
                        title=rule.title,
                        message=rule.message,
                        guidance=rule.guidance,
                        span=doc.span(start, end),
                        origin=Origin.RULE,
                        tags=list(rule.tags),
                        value=value,
                    )
                )
            if doc.has_obfuscation and doc.normalized and rule.category in _SHADOW_CATEGORIES:
                for m in compiled.finditer(doc.normalized):
                    n_start, n_end = m.span(rule.group)
                    if n_start < 0 or n_start == n_end:
                        continue
                    start, end = doc.map_normalized_span(n_start, n_end)
                    if (rule.id, start, end) in seen or not doc.in_scope(start, end):
                        continue
                    norm_value = doc.normalized[n_start:n_end]
                    if rule.validator is not None and not rule.validator(norm_value):
                        continue
                    seen.add((rule.id, start, end))
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            detector=self.name,
                            category=rule.category,
                            severity=rule.severity_by_direction.get(doc.direction, rule.severity),
                            confidence=rule.confidence,
                            title=rule.title,
                            message=f"{rule.message} (Detected through de-obfuscation shadow view.)",
                            guidance=rule.guidance,
                            span=doc.span(start, end),
                            origin=Origin.RULE,
                            tags=[*rule.tags, "deobfuscated"],
                            value=doc.text[start:end],
                        )
                    )
        return findings
