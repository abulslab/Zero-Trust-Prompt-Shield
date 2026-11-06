# Roadmap

## Delivered in 1.0

- Rule-based detectors: credentials (22 formats), personal and financial data with checksums, internal
  infrastructure, confidentiality markers, restricted terms, entropy.
- Coordinate-preserving de-obfuscation shadow view (invisible Unicode controls and Cyrillic/Greek/full-width homoglyphs).
- Injection and obfuscation defence, aware of direction: overrides, personas, role markers, prompt extraction, tool
  hijack, hidden markup, invisible characters, encoded instructions, markdown-image exfiltration.
- Verified AI review with redaction before the model and reported rejections.
- Reversible (`placeholder`, `synthetic`) and one-way (`mask`) redaction; guarded chat gateway with per-request canary
  tripwires and cross-boundary taint tracking.
- Agent tool-call argument guard (`POST /v1/guard/tool`) and OpenAI-compatible proxy (`POST /v1/chat/completions`).
- Prompt linter (16 checks across 5 dimensions) and checked optimiser.
- Policy packs as YAML; tamper-evident SHA-256 hash-chained audit trail without content; HMAC-keyed fingerprints and
  feedback-driven suppressions.
- API, CLI (SARIF + `audit-verify`), GitHub Action, pre-commit hook, web UI; labelled benchmark + 90-variant
  adversarial mutation suite.

## Next

| Phase | Theme | Scope |
|---|---|---|
| 1.1 | Streaming gateway | Server-sent events (`stream=true`) on `/v1/chat/completions` with sliding-window incremental output inspection. |
| 1.2 | SDKs | Python and TypeScript middleware packages for LangChain, LlamaIndex and MCP tool servers. |
| 1.3 | Detection depth | Optional local NER model for names and addresses; regional packs (EU national IDs, UK NINO, Indian Aadhaar/PAN); custom regex rules in policy packs. |
| 1.4 | Prompt operations | Prompt library with versions and lint history; A/B evaluation of rewrites against test inputs with an LLM judge from another model family, gated on measured agreement with people. |
| 1.5 | Enterprise | Postgres audit store, OIDC, per-team policies, SIEM export (CEF/OTLP), OpenTelemetry traces, Helm chart. |
| 1.6 | Browser | Extension that inspects what is pasted into AI chat sites, using the same API and policies. |

Each phase ships with tests, benchmark samples for any new detector, and an ADR for any new decision.
