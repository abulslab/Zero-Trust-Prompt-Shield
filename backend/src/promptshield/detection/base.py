"""Detector port and the shared document view every detector works on."""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

from promptshield.domain import Category, ContentType, Direction, Finding, Origin, Severity, Span


class Document:
    """The text under inspection plus what detectors need to know about it.

    For a diff, only added lines are in scope: removed and context lines are already in the repository
    and are not what the author is about to share.
    """

    def __init__(self, text: str, content_type: ContentType, direction: Direction) -> None:
        self.text = text
        self.content_type = content_type
        self.direction = direction
        self._line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
        self._scope = self._diff_scope(text) if content_type == ContentType.DIFF else None

    def span(self, start: int, end: int) -> Span:
        line_index = bisect.bisect_right(self._line_starts, start) - 1
        return Span(start=start, end=end, line=line_index + 1, column=start - self._line_starts[line_index] + 1)

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


class PatternDetector:
    """Runs a set of `PatternRule`s. Most detectors are just a named rule list."""

    def __init__(self, name: str, rules: Iterable[PatternRule]) -> None:
        self.name = name
        self.rules = list(rules)

    def detect(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if doc.direction not in rule.directions:
                continue
            for m in rule.compiled().finditer(doc.text):
                start, end = m.span(rule.group)
                if start < 0 or start == end:
                    continue
                value = doc.text[start:end]
                if not doc.in_scope(start, end):
                    continue
                if rule.validator is not None and not rule.validator(value):
                    continue
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
        return findings
