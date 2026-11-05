"""Prompt injection, jailbreaks, hidden characters, encoded payloads and exfiltration channels.

The same sentence means different things depending on where it sits: "ignore previous instructions" typed by a
user is a jailbreak attempt; inside a retrieved web page or tool result it is an indirect injection aimed at the
model, which is far more dangerous because nobody reviewing the prompt wrote it.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from promptshield.detection.base import Document, PatternDetector, PatternRule
from promptshield.domain import Category, Direction, Finding, Origin, Severity

_CTX = {Direction.CONTEXT: Severity.CRITICAL, Direction.OUTPUT: Severity.HIGH}
_ISOLATE = (
    "Treat this text as data, not instructions: keep it inside clearly delimited blocks, tell the model never to follow "
    "instructions found there, and strip or quarantine the instruction before it reaches the model."
)


def _rule(
    id_: str,
    title: str,
    message: str,
    pattern: str,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.85,
    category: Category = Category.INJECTION,
    guidance: str = _ISOLATE,
) -> PatternRule:
    return PatternRule(
        id=f"injection.{id_}",
        category=category,
        severity=severity,
        title=title,
        message=message,
        guidance=guidance,
        pattern=pattern,
        flags=re.IGNORECASE,
        confidence=confidence,
        severity_by_direction=dict(_CTX),
        tags=("owasp-llm01",),
    )


RULES: list[PatternRule] = [
    _rule(
        "override",
        "Instruction override",
        "Text asks the model to ignore or replace the instructions it was given.",
        r"\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}?\b(?:all|any|the|your|my|previous|prior|above|earlier|preceding|system|original)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules|directives|guidelines|context|messages?)\b",
    ),
    _rule(
        "new_instructions",
        "Injected instruction block",
        "Text announces new instructions or a new system prompt.",
        r"(?:^|\n)\s*(?:#+\s*)?(?:new|updated|real|actual|important|hidden)\s+(?:system\s+)?(?:instructions?|prompt|task)\s*[:\-]",
        Severity.HIGH,
        0.8,
    ),
    _rule(
        "role_markers",
        "Chat role markers",
        "Raw chat-template tokens or role headers can make the model treat injected text as a system or assistant turn.",
        r"<\|(?:im_start|im_end|system|endoftext|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<<SYS>>|(?:^|\n)\s*(?:###\s*)?(?:system|assistant)\s*:\s",
        Severity.HIGH,
        0.85,
    ),
    _rule(
        "persona_jailbreak",
        "Jailbreak persona",
        "Text tries to switch the model into an unrestricted persona or mode.",
        r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|from\s+now\s+on\s+you\s+are)\b[^.\n]{0,60}?\b(?:DAN|jailbr(?:oken|eak)|unrestricted|unfiltered|uncensored|without\s+(?:any\s+)?(?:restrictions|limits|filters|rules)|no\s+(?:rules|limits|restrictions))\b|\b(?:developer|god|debug|sudo)\s+mode\s+(?:enabled|on|activated)\b|\bDo\s+Anything\s+Now\b",
        Severity.HIGH,
        0.9,
    ),
    _rule(
        "prompt_leak",
        "System prompt extraction",
        "Text asks the model to reveal its system prompt or hidden instructions.",
        r"\b(?:reveal|show|print|repeat|output|display|tell\s+me|what\s+(?:is|are))\b[^.\n]{0,30}?\b(?:your|the)\s+(?:system\s+prompt|initial\s+(?:prompt|instructions)|hidden\s+(?:prompt|instructions)|instructions\s+above|original\s+instructions)\b",
        Severity.MEDIUM,
        0.85,
    ),
    _rule(
        "tool_hijack",
        "Tool or action hijack",
        "Text instructs the model to call tools, send data or take actions on its own initiative.",
        r"\b(?:call|invoke|use|run|execute)\s+(?:the\s+)?(?:tool|function|plugin|api|command)\b[^.\n]{0,60}?\b(?:send|post|email|upload|forward|delete|transfer)\b|\b(?:send|email|forward|upload|post)\s+(?:all|the|every|this)\b[^.\n]{0,40}?\b(?:conversation|chat\s+history|data|credentials|api\s+keys?|passwords?|files?|documents?)\b[^.\n]{0,40}?\bto\b",
        Severity.HIGH,
        0.75,
    ),
    _rule(
        "markdown_exfil",
        "Markdown image beacon",
        "An image link whose URL carries a query string can leak data to a third party the moment the answer is rendered.",
        r"!\[[^\]\n]{0,200}\]\(\s*https?://[^)\s?]{1,300}\?(?=[^)\s]{0,500}(?:\{|%7B|\$|=))[^)\s]{1,500}\)",
        Severity.HIGH,
        0.8,
        Category.EXFILTRATION,
        "Do not render images from untrusted answers, or allow only images from approved hosts without query strings.",
    ),
    _rule(
        "html_hidden",
        "Instruction hidden in markup",
        "Instructions inside an HTML comment or hidden element are invisible to people but read by the model.",
        r"<!--[^>]{0,400}?\b(?:ignore|instruction|assistant|system|prompt|you\s+must|do\s+not\s+tell)\b[\s\S]{0,400}?-->|<[^<>]{1,500}(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^>]*>",
        Severity.HIGH,
        0.8,
        Category.OBFUSCATION,
    ),
]

_INVISIBLE = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u2060": "word joiner",
    "\ufeff": "zero-width no-break space",
    "\u00ad": "soft hyphen",
    "\u202a": "bidi embedding",
    "\u202b": "bidi embedding",
    "\u202c": "bidi pop",
    "\u202d": "bidi override",
    "\u202e": "right-to-left override",
    "\u2066": "bidi isolate",
    "\u2067": "bidi isolate",
    "\u2068": "bidi isolate",
    "\u2069": "bidi isolate pop",
}
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_INSTRUCTION_WORDS = re.compile(
    r"\b(?:ignore|instruction|system|prompt|assistant|password|send|execute|reveal|you are)\b", re.I
)


class InjectionDetector:
    name = "injection"

    def __init__(self) -> None:
        self._patterns = PatternDetector(self.name, RULES)

    def detect(self, doc: Document) -> list[Finding]:
        return self._patterns.detect(doc) + self._invisible(doc) + self._encoded(doc)

    def _invisible(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        run_start: int | None = None
        kinds: set[str] = set()
        text = doc.text

        def flush(end: int) -> None:
            nonlocal run_start, kinds
            if run_start is not None and doc.in_scope(run_start, end):
                tag_chars = "unicode tag characters" in kinds
                findings.append(
                    Finding(
                        rule_id="obfuscation.invisible_chars",
                        detector=self.name,
                        category=Category.OBFUSCATION,
                        severity=Severity.CRITICAL
                        if tag_chars or doc.direction == Direction.CONTEXT
                        else Severity.HIGH,
                        confidence=0.95 if tag_chars else 0.8,
                        title="Hidden characters",
                        message=f"{end - run_start} invisible character(s) ({', '.join(sorted(kinds))}) can hide text or reorder what people see.",
                        guidance="Normalise the text (strip zero-width, bidi-control and tag characters) before it reaches the model.",
                        span=doc.span(run_start, end),
                        origin=Origin.RULE,
                        tags=["owasp-llm01"],
                        value=text[run_start:end],
                    )
                )
            run_start, kinds = None, set()

        for i, ch in enumerate(text):
            kind = _INVISIBLE.get(ch)
            if kind is None and 0xE0000 <= ord(ch) <= 0xE007F:
                kind = "unicode tag characters"
            if kind is None and unicodedata.category(ch) == "Cf" and ch not in "\u200e\u200f":
                kind = "format control"
            if kind:
                if run_start is None:
                    run_start = i
                kinds.add(kind)
            elif run_start is not None:
                flush(i)
        flush(len(text))
        return findings

    def _encoded(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        for m in _B64.finditer(doc.text):
            blob = m.group(0)
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            printable = sum(c.isprintable() or c.isspace() for c in decoded) / max(1, len(decoded))
            if printable < 0.95 or not _INSTRUCTION_WORDS.search(decoded):
                continue
            if not doc.in_scope(*m.span()):
                continue
            findings.append(
                Finding(
                    rule_id="obfuscation.encoded_instructions",
                    detector=self.name,
                    category=Category.OBFUSCATION,
                    severity=Severity.CRITICAL if doc.direction == Direction.CONTEXT else Severity.HIGH,
                    confidence=0.85,
                    title="Encoded instructions",
                    message="A base64 block decodes to instruction-like text, a common way to smuggle an injection past filters.",
                    guidance="Decode and inspect encoded blocks before passing them to a model, or drop them.",
                    span=doc.span(*m.span()),
                    origin=Origin.RULE,
                    tags=["owasp-llm01"],
                    value=blob,
                )
            )
        return findings


def detector() -> InjectionDetector:
    return InjectionDetector()
