"""HTTP API. `create_app` wires the Shield from settings; tests pass their own Shield."""

from __future__ import annotations

import hmac
import logging
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from promptshield import __version__
from promptshield.ai import build_gateway
from promptshield.ai.semantic import TAXONOMY
from promptshield.api.schemas import (
    BatchInspectRequest,
    FeedbackRequest,
    GuardRequest,
    InspectRequest,
    LintRequest,
    OpenAIChatRequest,
    OptimizeRequest,
    RedactRequest,
    RestoreRequest,
    ToolGuardRequest,
)
from promptshield.audit import SqliteAuditStore
from promptshield.config import Settings, get_settings
from promptshield.detection import BUILTIN
from promptshield.domain import Category
from promptshield.domain.models import set_fingerprint_key
from promptshield.eval.runner import run as run_benchmark
from promptshield.policy import PolicyStore
from promptshield.redaction import restore
from promptshield.service import InputTooLarge, InspectOptions, Shield

log = logging.getLogger("promptshield")


def build_shield(s: Settings) -> Shield:
    set_fingerprint_key(s.fingerprint_key.get_secret_value() if s.fingerprint_key else None)
    return Shield(
        policies=PolicyStore(s.policy_dir),
        gateway=build_gateway(s),
        audit=SqliteAuditStore(s.db_path),
        default_policy=s.default_policy,
        max_chars=s.max_chars,
    )


def create_app(settings: Settings | None = None, shield: Shield | None = None) -> FastAPI:
    s = settings or get_settings()
    logging.basicConfig(level=s.log_level, format='{"t":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}')
    sh = shield or build_shield(s)
    app = FastAPI(
        title="Zero-Trust Prompt Shield",
        version=__version__,
        description="Inspect, redact, guard and improve what goes into and comes out of LLMs. "
        "Rules decide; models only propose, and every proposal is verified against the text.",
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.shield = sh
    app.state.settings = s
    _security_middleware(app, s)
    # Added last so it is the outermost layer: rejections (401, 429, 413) still carry CORS headers and reach the UI.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-Id", "X-Shield-Source"],
        expose_headers=[
            "X-Request-Id",
            "X-Shield-Decision",
            "X-Shield-Risk-Score",
            "X-Shield-Placeholders",
            "X-Shield-Canary-Verified",
        ],
        allow_credentials=False,
    )
    _routes(app, sh, s)
    return app


def _security_middleware(app: FastAPI, s: Settings) -> None:
    hits: dict[str, deque[float]] = {}
    api_key = s.api_key.get_secret_value() if s.api_key else None

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        started = time.perf_counter()
        path = request.url.path
        if path.startswith("/v1") and request.method != "OPTIONS":
            if api_key:
                supplied = (
                    request.headers.get("x-api-key")
                    or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
                )
                if not supplied or not hmac.compare_digest(supplied, api_key):
                    return _problem(401, "Missing or invalid API key.", rid)
            client = request.client.host if request.client else "?"
            now = time.monotonic()
            if len(hits) > 10_000:  # forget idle clients so many distinct addresses cannot grow memory without bound
                for key in [k for k, w in hits.items() if not w or now - w[-1] > 60]:
                    del hits[key]
            window = hits.setdefault(client, deque())
            while window and now - window[0] > 60:
                window.popleft()
            if len(window) >= s.rate_limit_per_minute:
                return _problem(429, "Rate limit exceeded; try again in a minute.", rid)
            window.append(now)
            try:
                length = int(request.headers.get("content-length") or 0)
            except ValueError:
                return _problem(400, "Invalid Content-Length header.", rid)
            if length > s.max_chars * 4 + 65_536:
                return _problem(413, "Request body is too large.", rid)
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        # Never log content: method, path, status and duration only.
        log.info(
            "%s %s %s %dms rid=%s",
            request.method,
            path,
            response.status_code,
            int((time.perf_counter() - started) * 1000),
            rid,
        )
        return response


def _problem(status: int, detail: str, rid: str | None = None) -> JSONResponse:
    return JSONResponse(
        {"title": "Request rejected", "status": status, "detail": detail},
        status_code=status,
        headers={"X-Request-Id": rid or ""},
        media_type="application/problem+json",
    )


def _opts(r: InspectRequest | RedactRequest, *, source: str) -> InspectOptions:
    return InspectOptions(
        direction=r.direction,
        content_type=r.content_type,
        policy_id=r.policy,
        ai=r.ai,
        redaction=r.redaction if isinstance(r, InspectRequest) else r.mode,
        source=source,
    )


def _routes(app: FastAPI, sh: Shield, s: Settings) -> None:
    def check_policy(pid: str | None) -> None:
        if pid is not None:
            try:
                sh.policies.get(pid)
            except KeyError:
                raise HTTPException(404, f"Unknown policy '{pid}'.") from None

    def source_of(request: Request) -> str:
        return (request.headers.get("x-shield-source") or "api")[:20]

    @app.exception_handler(InputTooLarge)
    async def too_large(_: Request, e: InputTooLarge) -> JSONResponse:
        return _problem(413, str(e))

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"])
    def readyz() -> dict[str, Any]:
        sh.audit.stats() if sh.audit else None
        return {"status": "ready", "storage": "sqlite", "ai": sh.gateway.describe()}

    @app.get("/v1/meta", tags=["meta"])
    def meta() -> dict[str, Any]:
        return {
            "version": __version__,
            "ai": {**sh.gateway.describe(), "available": sh.gateway.available},
            "default_policy": sh.default_policy,
            "limits": {
                "max_chars": s.max_chars,
                "ai_max_input_chars": s.ai_max_input_chars,
                "rate_limit_per_minute": s.rate_limit_per_minute,
            },
            "detectors": list(BUILTIN),
            "categories": [c.value for c in Category],
            "semantic_taxonomy": {k: {"category": v.category.value, "title": v.title} for k, v in TAXONOMY.items()},
            "auth": bool(s.api_key),
        }

    @app.post("/v1/inspect", tags=["inspect"])
    def inspect(req: InspectRequest, request: Request) -> dict[str, Any]:
        check_policy(req.policy)
        return sh.inspect(req.content, _opts(req, source=source_of(request))).public()

    @app.post("/v1/inspect/batch", tags=["inspect"])
    def inspect_batch(req: BatchInspectRequest, request: Request) -> dict[str, Any]:
        results = []
        for item in req.items:
            check_policy(item.policy)
            results.append(sh.inspect(item.content, _opts(item, source=source_of(request))).public())
        worst = max(results, key=lambda r: ["allow", "warn", "redact", "block"].index(r["decision"]["action"]))
        return {"results": results, "decision": worst["decision"]}

    @app.post("/v1/redact", tags=["redact"])
    def redact_(req: RedactRequest, request: Request) -> dict[str, Any]:
        check_policy(req.policy)
        result, red = sh.redact(req.content, _opts(req, source=source_of(request)), all_findings=req.scope == "all")
        return {
            "redacted": red.text,
            "mapping": red.mapping,  # returned to the caller only; the server keeps nothing
            "replaced": len(red.segments),
            "inspection": result.public() | {"redacted": None},
        }

    @app.post("/v1/restore", tags=["redact"])
    def restore_(req: RestoreRequest) -> dict[str, Any]:
        text, unknown = restore(req.content, req.mapping)
        return {"restored": text, "unknown_placeholders": unknown}

    @app.post("/v1/prompt/lint", tags=["prompt"])
    def lint_(req: LintRequest) -> dict[str, Any]:
        if len(req.prompt) > s.max_chars:
            raise InputTooLarge(f"Prompt is {len(req.prompt)} characters; the limit is {s.max_chars}.")
        report, inspection = sh.lint(req.prompt)
        return {"lint": _lint_public(report), "inspection": inspection.public()}

    @app.post("/v1/prompt/optimize", tags=["prompt"])
    def optimize(req: OptimizeRequest) -> dict[str, Any]:
        if len(req.prompt) > s.ai_max_input_chars:
            raise InputTooLarge(
                f"Prompt is {len(req.prompt)} characters; the optimiser limit is {s.ai_max_input_chars}."
            )
        r = sh.optimizer.optimize(req.prompt, req.goal, req.ai)
        return {
            "engine": r.engine,
            "rewrite": r.rewrite,
            "safe_rewrite": r.safe_rewrite,
            "changes": r.changes,
            "assumptions": r.assumptions,
            "checks": [c.__dict__ for c in r.checks],
            "before": _lint_public(r.before),
            "after": _lint_public(r.after),
            "model": r.model,
            "model_error": r.model_error,
            "rejected_model_rewrite": r.rejected_model_rewrite,
            "notes": r.notes,
        }

    @app.post("/v1/guard/chat", tags=["guard"])
    def guard_chat(req: GuardRequest, request: Request) -> dict[str, Any]:
        check_policy(req.policy)
        g = sh.guard(
            [m.model_dump() for m in req.messages],
            req.policy,
            source=source_of(request) if source_of(request) != "api" else "guard",
        )
        return {
            "status": g.status,
            "answer": g.answer,
            "sent": g.sent,
            "placeholders": g.placeholders,
            "canary_verified": g.canary_verified,
            "tainted_sinks": g.tainted_sinks,
            "model": g.model,
            "error": g.error,
            "input": g.input.public() | {"redacted": None},
            "output": g.output.public() | {"redacted": None} if g.output else None,
        }

    @app.post("/v1/guard/tool", tags=["guard"])
    def guard_tool(req: ToolGuardRequest, request: Request) -> dict[str, Any]:
        check_policy(req.policy)
        res = sh.guard_tool(
            tool_name=req.tool_name,
            arguments=req.arguments,
            untrusted_text=req.untrusted_text,
            policy_id=req.policy,
            source=source_of(request) if source_of(request) != "api" else "tool_guard",
        )
        return {
            "allowed": res.allowed,
            "tool_name": res.tool_name,
            "decision": res.decision.model_dump(mode="json"),
            "redacted_arguments": res.redacted_arguments,
            "tainted_sinks": res.tainted_sinks,
            "inspection": res.inspection.public() | {"redacted": None},
        }

    @app.post("/v1/chat/completions", tags=["guard"])
    def openai_chat_completions(req: OpenAIChatRequest, request: Request) -> JSONResponse:
        check_policy(req.policy)
        g = sh.guard(
            [m.model_dump() for m in req.messages],
            req.policy,
            source=source_of(request) if source_of(request) != "api" else "openai_proxy",
        )
        decision_action = (
            g.output.decision.action.value
            if g.output and g.status == "blocked_output"
            else g.input.decision.action.value
        )
        risk_score = (
            g.output.decision.risk_score if g.output and g.status == "blocked_output" else g.input.decision.risk_score
        )
        headers = {
            "X-Shield-Decision": decision_action,
            "X-Shield-Risk-Score": str(risk_score),
            "X-Shield-Placeholders": str(g.placeholders),
            "X-Shield-Canary-Verified": "true" if g.canary_verified else "false",
        }
        if g.status in {"blocked_input", "blocked_output"}:
            summary = g.output.summary if g.output and g.status == "blocked_output" else g.input.summary
            return JSONResponse(
                status_code=400,
                headers=headers,
                content={
                    "error": {
                        "message": f"Zero-Trust Prompt Shield ({g.status}): {summary}",
                        "type": "promptshield_policy_violation",
                        "code": g.status,
                    }
                },
            )
        if g.status == "model_unavailable":
            return JSONResponse(
                status_code=503,
                headers=headers,
                content={
                    "error": {
                        "message": g.error or "No upstream AI model is configured.",
                        "type": "model_unavailable",
                        "code": "model_unavailable",
                    }
                },
            )
        return JSONResponse(
            status_code=200,
            headers=headers,
            content={
                "id": f"chatcmpl-{uuid.uuid4().hex[:16]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": (g.model or {}).get("model") or req.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": g.answer or ""},
                        "finish_reason": "stop",
                    }
                ],
                "shield": {
                    "status": g.status,
                    "placeholders": g.placeholders,
                    "canary_verified": g.canary_verified,
                    "tainted_sinks": g.tainted_sinks,
                },
            },
        )

    @app.get("/v1/policies", tags=["policy"])
    def policies() -> list[dict[str, Any]]:
        return [p.model_dump(mode="json") for p in sh.policies.all()]

    @app.get("/v1/policies/{policy_id}", tags=["policy"])
    def policy(policy_id: str) -> dict[str, Any]:
        check_policy(policy_id)
        return sh.policies.get(policy_id).model_dump(mode="json")

    @app.get("/v1/audit", tags=["audit"])
    def audit(
        limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), action: str | None = None
    ) -> list[dict[str, Any]]:
        return sh.audit.recent(limit, offset, action) if sh.audit else []

    @app.get("/v1/audit/verify", tags=["audit"])
    def audit_verify() -> dict[str, Any]:
        if sh.audit is None:
            return {"valid": True, "checked": 0, "total": 0, "head_hash": "GENESIS", "broken_at": None}
        return sh.audit.verify_chain()

    @app.get("/v1/audit/{inspection_id}", tags=["audit"])
    def audit_item(inspection_id: str) -> dict[str, Any]:
        item = sh.audit.get(inspection_id) if sh.audit else None
        if item is None:
            raise HTTPException(404, "No such inspection.")
        return item

    @app.get("/v1/stats", tags=["audit"])
    def stats() -> dict[str, Any]:
        return sh.audit.stats() if sh.audit else {}

    @app.get("/v1/feedback", tags=["feedback"])
    def feedback() -> list[dict[str, Any]]:
        return sh.audit.list_feedback() if sh.audit else []

    @app.post("/v1/feedback", tags=["feedback"], status_code=201)
    def add_feedback(req: FeedbackRequest) -> dict[str, str]:
        if sh.audit is None:
            raise HTTPException(503, "Feedback needs the audit store.")
        sh.audit.add_feedback(req.finding_id, req.rule_id, req.verdict, req.note, req.preview, req.inspection_id)
        return {
            "status": "recorded",
            "effect": "suppressed in future inspections" if req.verdict == "false_positive" else "confirmed",
        }

    @app.delete("/v1/feedback/{finding_id}", tags=["feedback"])
    def delete_feedback(finding_id: str) -> dict[str, str]:
        if sh.audit is None or not sh.audit.delete_feedback(finding_id):
            raise HTTPException(404, "No feedback for that finding.")
        return {"status": "deleted"}

    @app.post("/v1/benchmark", tags=["evaluation"])
    def benchmark() -> dict[str, Any]:
        return run_benchmark(sh).public()


def _lint_public(r: Any) -> dict[str, Any]:
    return {
        "score": r.score,
        "grade": r.grade,
        "dimensions": r.dimensions,
        "issues": [i.__dict__ for i in r.issues],
        "stats": r.stats,
        "variables": r.variables,
    }


def app_factory() -> FastAPI:
    return create_app()
