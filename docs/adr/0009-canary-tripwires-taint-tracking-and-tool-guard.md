# 9. Ephemeral canary tripwires, cross-boundary taint tracking and tool-call guard

Status: accepted

## Context
Pattern rules on input and output cannot catch two classes of indirect prompt-injection failures:
1. A novel jailbreak or translation trick that convinces the model to leak its system prompt without matching known
   extraction phrases.
2. An untrusted document or tool output that introduces an innocent-looking domain (`mirror.vendor-note.example`) and
   convinces the model to emit a link, email or tool call targeting that domain with conversation data.

Furthermore, modern LLM agents act primarily by invoking structured tools (`http_get`, `send_email`, `run_query`) rather
than returning plain prose.

## Decision
1. **Ephemeral canary tripwires (`exfiltration.canary_leak`)**: On every `Shield.guard` call, the shield generates a
   random per-request token (`ZXQ-<hex>`) injected into the system boundary instruction. If the token (raw, case-folded
   or base64-encoded) appears anywhere in the model's reply, the output is blocked with certainty `1.0`.
2. **Cross-boundary taint tracking (`exfiltration.tainted_sink`)**: `Shield.guard` records external domains introduced
   exclusively in untrusted `context`/`tool`/`document` messages (and absent from `system`/`user` messages). Any URL or
   email in the model's output or tool-call arguments targeting a tainted domain is blocked.
3. **Agent tool-call guard (`POST /v1/guard/tool`)**: Structured tool arguments are inspected before execution for
   secrets, PII, SSRF targets (cloud metadata IPs, loopback, local schemes), shell injection syntax and tainted sinks.

## Consequences
- System-prompt leaks are caught deterministically even on zero-day jailbreak phrasing.
- Untrusted context cannot introduce new outbound exfiltration destinations into model answers or tool calls.
- Agent frameworks can gate every tool invocation through a single synchronous check.

