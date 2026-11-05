"""HTTP request bodies. Responses are plain dicts built from the domain's `public()` views."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from promptshield.domain import ContentType, Direction
from promptshield.redaction import RedactionMode

AiMode = Literal["off", "auto", "on"]


class InspectRequest(BaseModel):
    content: str = Field(description="Text to inspect.")
    direction: Direction = Direction.INPUT
    content_type: ContentType = ContentType.TEXT
    policy: str | None = Field(default=None, description="Policy pack id; the server default when omitted.")
    ai: AiMode = "auto"
    redaction: RedactionMode = RedactionMode.MASK


class RedactRequest(BaseModel):
    content: str
    direction: Direction = Direction.INPUT
    content_type: ContentType = ContentType.TEXT
    policy: str | None = None
    ai: AiMode = "off"
    mode: RedactionMode = RedactionMode.PLACEHOLDER
    scope: Literal["all", "policy"] = Field(
        default="all", description="'all' findings, or only those the policy says to redact."
    )


class RestoreRequest(BaseModel):
    content: str
    mapping: dict[str, str]


class LintRequest(BaseModel):
    prompt: str


class OptimizeRequest(BaseModel):
    prompt: str
    goal: str | None = Field(default=None, max_length=500)
    ai: bool = True


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "context", "document"] = "user"
    content: str


class GuardRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=50)
    policy: str | None = None


class ToolGuardRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=120)
    arguments: dict[str, Any] = Field(default_factory=dict)
    untrusted_text: str | None = Field(
        default=None,
        description="Optional untrusted context (e.g. retrieved docs) to enforce cross-boundary taint tracking.",
    )
    policy: str | None = None


class OpenAIChatRequest(BaseModel):
    model: str = "promptshield-guard"
    messages: list[ChatMessage] = Field(min_length=1, max_length=50)
    policy: str | None = None


class FeedbackRequest(BaseModel):
    finding_id: str = Field(min_length=8, max_length=64, description="The finding's id (its fingerprint).")
    rule_id: str
    verdict: Literal["false_positive", "true_positive"]
    note: str | None = Field(default=None, max_length=500)
    preview: str | None = Field(default=None, max_length=80)
    inspection_id: str | None = None


class BatchInspectRequest(BaseModel):
    items: list[InspectRequest] = Field(min_length=1, max_length=100)
