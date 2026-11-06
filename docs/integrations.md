# Integrations

## REST API

Interactive OpenAPI documentation is served at `/docs`. All endpoints are under `/v1`; send `X-API-Key` when the
server sets `SHIELD_API_KEY`.

| Endpoint | Purpose |
|---|---|
| `POST /v1/inspect` | Inspect one text. Body: `content`, `direction` (input, context, output), `content_type` (text, prompt, code, diff, json), `policy`, `ai` (off, auto, on), `redaction` (mask, placeholder, synthetic). |
| `POST /v1/inspect/batch` | Up to 100 texts; returns each result and the most restrictive decision. |
| `POST /v1/redact` | Redacted text plus the reversible mapping (returned only to you). `mode`: `placeholder` (`<<EMAIL_1>>`), `synthetic` (`user1@redacted.invalid`, `192.0.2.1`), or `mask` (`[REDACTED:EMAIL]`). `scope`: all findings or only those the policy redacts. |
| `POST /v1/restore` | Put mapped placeholders or synthetic surrogates back into a model's answer. |
| `POST /v1/guard/chat` | Inspect, redact, inject a per-request canary token, call the configured model, inspect the answer (including canary leak & cross-boundary taint tracking), and restore. |
| `POST /v1/guard/tool` | Screen a structured agent tool call (`tool_name`, `arguments`, optional `untrusted_text`) for secrets, PII, SSRF targets, shell command injection and tainted sinks before execution. |
| `POST /v1/chat/completions` | Drop-in OpenAI-compatible chat completions proxy wrapping `Shield.guard` and returning `X-Shield-Decision`, `X-Shield-Risk-Score`, `X-Shield-Placeholders` and `X-Shield-Canary-Verified` headers. |
| `POST /v1/prompt/lint` | Score a prompt and list issues with fixes. |
| `POST /v1/prompt/optimize` | Checked rewrite of a prompt (model or structured). |
| `GET /v1/policies`, `GET /v1/policies/{id}` | Policy packs. |
| `GET /v1/audit`, `GET /v1/audit/{id}`, `GET /v1/audit/verify`, `GET /v1/stats` | Audit trail, tamper-evident SHA-256 hash chain verification, and aggregates. |
| `GET/POST/DELETE /v1/feedback` | Mark findings real or not an issue; suppressions. |
| `POST /v1/benchmark` | Run the labelled corpus and the 90-variant adversarial mutation resilience suite. |
| `GET /healthz`, `GET /readyz`, `GET /v1/meta` | Operations and capabilities. |

### Pattern 1: Redact (placeholder or synthetic), call, restore

```python
import httpx

shield = httpx.Client(base_url="http://localhost:5380")
red = shield.post(
    "/v1/redact",
    json={"content": prompt, "mode": "synthetic", "scope": "policy"},
).json()
if red["inspection"]["decision"]["action"] == "block":
    raise RuntimeError(red["inspection"]["decision"]["reasons"])
answer = my_llm(red["redacted"])
checked = shield.post("/v1/inspect", json={"content": answer, "direction": "output"}).json()
if checked["decision"]["action"] != "block":
    answer = shield.post("/v1/restore", json={"content": answer, "mapping": red["mapping"]}).json()["restored"]
```

### Pattern 2: Gate agent tool execution (`POST /v1/guard/tool`)

```python
check = shield.post(
    "/v1/guard/tool",
    json={
        "tool_name": tool_call.name,
        "arguments": tool_call.arguments,
        "untrusted_text": retrieved_context,
    },
).json()
if not check["allowed"]:
    raise PermissionError(f"Tool blocked by Prompt Shield: {check['inspection']['summary']}")
result = run_tool(tool_call.name, check["redacted_arguments"])
```

### Pattern 3: Drop-in OpenAI SDK client proxy (`POST /v1/chat/completions`)

Point any OpenAI-compatible client at `/v1` to get automatic input inspection, reversible redaction, ephemeral canary
tripwires, cross-boundary taint tracking and output restoration:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:5380/v1", api_key="<your-shield-api-key>")
resp = client.chat.completions.create(
    model="promptshield-guard",
    messages=[{"role": "user", "content": "Draft a follow-up to user1@example.com"}],
)
print(resp.choices[0].message.content)
```

### Pattern 4: Screen RAG documents before indexing

```python
r = shield.post(
    "/v1/inspect",
    json={"content": chunk, "direction": "context", "policy": "rag-ingestion", "redaction": "mask"},
).json()
if r["decision"]["action"] == "block":
    quarantine(chunk, r["summary"])
else:
    index(r["redacted"] or chunk)
```

## CLI

```bash
promptshield scan [paths…|-] [--diff [REF]] [--direction input|context|output] [--policy ID]
                  [--format text|json|sarif] [--fail-on allow|warn|redact|block] [--ai]
promptshield lint [path|-] [--min-score N] [--format text|json]
promptshield redact [path|-] [--mode placeholder|synthetic|mask] [--mapping file.json]
promptshield audit-verify [--db PATH]
promptshield serve [--host H] [--port P] [--reload]
promptshield benchmark
```

Exit codes: `0` below the `--fail-on` threshold (or valid chain/benchmark), `1` at or above it, `2` usage or runtime error.

## GitHub Action

```yaml
name: prompt-shield
on: [pull_request]
permissions: { contents: read, security-events: write }
jobs:
  shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: abulslab/Zero-Trust-Prompt-Shield@main
        with:
          diff-base: origin/${{ github.base_ref }}   # scan only what the PR adds
          fail-on: block
          sarif: shield.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: shield.sarif }
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/abulslab/Zero-Trust-Prompt-Shield
    rev: main
    hooks:
      - id: promptshield        # scans staged changes, blocks on secrets
```
