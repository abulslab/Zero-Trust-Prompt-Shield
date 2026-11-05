"""Prompt linter: deterministic checks for what makes prompts unreliable, with a fix for each.

Scores five dimensions (clarity, specificity, structure, safety, efficiency) from 0 to 100. The checks are
heuristics and say so: they flag likely problems, they do not judge the task.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Dimension = Literal["clarity", "specificity", "structure", "safety", "efficiency"]
DIMENSIONS: tuple[Dimension, ...] = ("clarity", "specificity", "structure", "safety", "efficiency")


@dataclass
class LintIssue:
    id: str
    dimension: Dimension
    severity: Literal["info", "low", "medium", "high"]
    title: str
    message: str
    suggestion: str
    start: int | None = None
    end: int | None = None
    evidence: str | None = None


@dataclass
class LintReport:
    score: int
    grade: str
    dimensions: dict[str, int]
    issues: list[LintIssue] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    variables: list[str] = field(default_factory=list)


_PENALTY = {"info": 2, "low": 6, "medium": 12, "high": 25}
_VARIABLE = re.compile(r"\{\{\s*[\w.-]+\s*\}\}|\{[A-Za-z_][\w.]*\}|\$\{[\w.]+\}|<<[A-Z0-9_]+>>|\[[A-Z][A-Z0-9_ ]{2,}\]")
_ROLE = re.compile(r"(?i)\b(?:you are|you're|act as|as an? [a-z]+|your role|role\s*:|persona\s*:)")
_FORMAT = re.compile(
    r"(?i)\b(?:json|yaml|csv|markdown|table|bullet|list|numbered|format|schema|headings?|sections?|code block|"
    r"\d+\s*(?:words|sentences|paragraphs|bullets|items|points|lines|characters)|one (?:word|sentence|paragraph)|"
    r"respond with|return (?:only|a|an|the)|output (?:only|a|an|the))\b"
)
_CONTEXT = re.compile(
    r"(?i)\b(?:context|background|audience|because|goal|purpose|so that|in order to|for (?:a|an|the|my) [a-z]+)\b"
)
_CONSTRAINT = re.compile(
    r"(?i)\b(?:must|should|only|avoid|do not|don't|never|always|at most|at least|no more than|limit|constraint|within)\b"
)
_VAGUE = re.compile(
    r"(?i)\b(?:some|stuff|things?|etc\.?|and so on|whatever|somehow|kind of|sort of|a bit|nice|good|better|properly|appropriate(?:ly)?|various|several|a few|as needed)\b"
)
_UNBOUNDED = re.compile(
    r"(?i)\b(?:everything|all possible|every possible|as much as possible|exhaustive(?:ly)?|anything you can)\b"
)
_NEGATIVE = re.compile(r"(?i)\b(?:don't|do not|never|avoid|must not|shouldn't|should not|no)\b")
_DELIMITED = re.compile(r"```|\"\"\"|<[a-z_]+>[\s\S]*</[a-z_]+>|^-{3,}$|^#{1,6} ", re.M)
_CONFLICTS = [
    (
        re.compile(r"(?i)\b(?:brief|short|concise|succinct|one sentence)\b"),
        re.compile(r"(?i)\b(?:detailed|comprehensive|in[- ]depth|thorough|exhaustive|elaborate)\b"),
        "brief",
        "detailed",
    ),
    (re.compile(r"(?i)\bformal\b"), re.compile(r"(?i)\b(?:casual|informal|chatty)\b"), "formal", "casual"),
    (
        re.compile(r"(?i)\bonly (?:return|output|respond with) (?:json|code)\b"),
        re.compile(r"(?i)\b(?:explain|explanation|walk me through)\b"),
        "only machine output",
        "an explanation",
    ),
]
_WEAK_START = re.compile(r"^\s*(?:it|this|that|these|those|they|the above|same as before)\b", re.I)
_CAPS = re.compile(r"\b[A-Z]{4,}(?:\s+[A-Z]{2,}){2,}\b")


def estimate_tokens(text: str) -> int:
    """Rough, provider-neutral estimate (about 4 characters per token for English, more for code)."""
    return max(1, round(len(text) / 4)) if text else 0


def lint(prompt: str) -> LintReport:
    text = prompt or ""
    words = re.findall(r"\b\w+\b", text)
    issues: list[LintIssue] = []

    def add(
        id_: str,
        dim: Dimension,
        sev: Literal["info", "low", "medium", "high"],
        title: str,
        msg: str,
        fix: str,
        m: re.Match[str] | None = None,
    ) -> None:
        issues.append(
            LintIssue(
                id_,
                dim,
                sev,
                title,
                msg,
                fix,
                m.start() if m else None,
                m.end() if m else None,
                m.group(0) if m else None,
            )
        )

    if len(words) < 8:
        add(
            "PQ001",
            "specificity",
            "high",
            "Underspecified prompt",
            f"Only {len(words)} words. Models fill gaps with guesses.",
            "State the task, the input, who the answer is for and what a good answer looks like.",
        )
    if not _ROLE.search(text) and len(words) >= 8:
        add(
            "PQ002",
            "clarity",
            "low",
            "No role or perspective",
            "The prompt does not say who the model should be or whose perspective to take.",
            "Open with a role, for example: 'You are a senior QA engineer reviewing a release plan.'",
        )
    if not _FORMAT.search(text):
        add(
            "PQ003",
            "structure",
            "medium",
            "No output format",
            "The prompt does not say what shape the answer should take.",
            "Specify the format and length: 'Answer as a Markdown table with columns X, Y' or 'Return JSON matching this schema'.",
        )
    if not _CONTEXT.search(text) and len(words) >= 8:
        add(
            "PQ004",
            "specificity",
            "low",
            "No context or goal",
            "The prompt gives no background, audience or purpose.",
            "Add one or two sentences on why you need this and who will read it.",
        )
    if not _CONSTRAINT.search(text) and len(words) >= 15:
        add(
            "PQ005",
            "specificity",
            "low",
            "No constraints",
            "Nothing bounds the answer (scope, length, sources, what to avoid).",
            "Add explicit constraints: scope, length, what to include and what to leave out.",
        )
    vague = list(_VAGUE.finditer(text))
    if len(vague) >= 2:
        add(
            "PQ006",
            "clarity",
            "medium" if len(vague) >= 4 else "low",
            "Vague wording",
            f"{len(vague)} vague words ({', '.join(sorted({v.group(0).lower() for v in vague})[:6])}).",
            "Replace vague words with measurable criteria (numbers, names, examples).",
            vague[0],
        )
    if (m := _UNBOUNDED.search(text)) is not None:
        add(
            "PQ007",
            "efficiency",
            "medium",
            "Unbounded request",
            "Asking for everything produces long, unfocused answers and wastes tokens.",
            "Ask for the top N items, ranked by a stated criterion.",
            m,
        )
    for a, b, la, lb in _CONFLICTS:
        ma, mb = a.search(text), b.search(text)
        if ma and mb:
            add(
                "PQ008",
                "clarity",
                "high",
                "Conflicting instructions",
                f"The prompt asks for both {la} and {lb}.",
                "Choose one, or say which applies where (for example a one-line summary followed by details).",
                ma,
            )
    if text.count("?") > 3:
        add(
            "PQ009",
            "structure",
            "medium",
            "Several questions at once",
            f"{text.count('?')} questions in one prompt; later ones tend to get shallow answers.",
            "Number the questions, or split them into separate prompts.",
        )
    negatives = list(_NEGATIVE.finditer(text))
    if len(negatives) > 4:
        add(
            "PQ010",
            "clarity",
            "low",
            "Mostly negative instructions",
            f"{len(negatives)} 'don't/never/avoid' instructions; models follow positive instructions more reliably.",
            "Rephrase as what to do: 'Write in plain English' instead of 'Don't use jargon'.",
        )
    if (m := _CAPS.search(text)) is not None:
        add(
            "PQ011",
            "clarity",
            "info",
            "Shouting",
            "Capitalised phrases rarely help modern models and can make them over-apply a rule.",
            "Use normal case and explain why the rule matters instead.",
            m,
        )
    lines = text.splitlines()
    if len(lines) > 12 and not _DELIMITED.search(text):
        add(
            "PQ012",
            "structure",
            "medium",
            "Data not delimited",
            "A long prompt mixes instructions and data without separators; the model may treat data as instructions.",
            "Put pasted data inside clear delimiters (```...``` or <document>...</document>) and keep instructions outside.",
        )
    if (m := _WEAK_START.match(text)) is not None:
        add(
            "PQ013",
            "clarity",
            "medium",
            "Dangling reference",
            "The prompt starts by referring to something ('it', 'this') the model cannot see.",
            "Name the thing you mean, or include it.",
            m,
        )
    unresolved = [v for v in _VARIABLE.finditer(text) if not v.group(0).startswith("<<")]
    if unresolved:
        add(
            "PQ014",
            "safety",
            "medium",
            "Unfilled template variables",
            f"{len(unresolved)} template variable(s) are still unfilled ({', '.join(sorted({v.group(0) for v in unresolved})[:5])}).",
            "Fill the variables before sending, or confirm the template engine will.",
            unresolved[0],
        )
    tokens = estimate_tokens(text)
    if tokens > 6000:
        add(
            "PQ015",
            "efficiency",
            "medium",
            "Very long prompt",
            f"About {tokens} tokens. Cost and latency grow with length, and instructions get lost in long context.",
            "Move reference material into retrieval, summarise it, or put instructions at the start and end.",
        )
    if (
        len(words) >= 8
        and not re.search(r"(?i)\b(?:example|e\.g\.|for instance|such as|like this)\b", text)
        and _FORMAT.search(text)
        and len(words) > 40
    ):
        add(
            "PQ016",
            "specificity",
            "info",
            "No example",
            "One short example of the desired output usually improves format adherence.",
            "Add a minimal example of a good answer.",
        )

    dims = {d: 100 for d in DIMENSIONS}
    for i in issues:
        dims[i.dimension] = max(0, dims[i.dimension] - _PENALTY[i.severity])
    score = _overall(issues)
    return LintReport(
        score=score,
        grade=_grade(score),
        dimensions={str(k): v for k, v in dims.items()},
        issues=issues,
        stats={"characters": len(text), "words": len(words), "lines": len(lines), "estimated_tokens": tokens},
        variables=sorted({v.group(0) for v in _VARIABLE.finditer(text)}),
    )


def apply_safety(report: LintReport, sensitive_findings: int) -> LintReport:
    """Fold the shield's own inspection into the safety dimension: a prompt that leaks data is not a good prompt."""
    if sensitive_findings:
        report.issues.append(
            LintIssue(
                "PQ100",
                "safety",
                "high",
                "Sensitive data in the prompt",
                f"Prompt Shield found {sensitive_findings} sensitive item(s) in this prompt.",
                "Redact them (placeholders keep the prompt usable) before sending.",
            )
        )
        report.dimensions["safety"] = max(0, report.dimensions["safety"] - _PENALTY["high"])
        report.score = _overall(report.issues)
        report.grade = _grade(report.score)
    return report


def _overall(issues: list[LintIssue]) -> int:
    """Penalties add up across dimensions: three medium problems make a mediocre prompt, wherever they are."""
    return max(0, 100 - sum(_PENALTY[i.severity] for i in issues))


def _grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 55 else "E"
