# Roadmap

## Delivered in 1.0

- Rule-based detectors: credentials (20+ formats), personal and financial data with checksums, internal
  infrastructure, confidentiality markers, restricted terms, entropy.
- Injection and obfuscation defence, aware of direction: overrides, personas, role markers, prompt extraction, tool
  hijack, hidden markup, invisible characters, encoded instructions, markdown-image exfiltration.
- Verified AI review with redaction before the model and reported rejections.
- Reversible and one-way redaction; guarded chat gateway.
- Prompt linter and checked optimiser.
- Policy packs as YAML; audit trail without content; feedback-driven suppressions.
- API, CLI (SARIF), GitHub Action, pre-commit hook, web UI; labelled benchmark.

## Next

| Phase | Theme | Scope |
|---|---|---|
| 1.1 | Gateway | OpenAI-compatible proxy endpoint (`/v1/chat/completions`) so existing clients route through the shield by changing a base URL; streaming responses with incremental output inspection. |
| 1.2 | SDKs | Python and TypeScript middleware for LangChain, LlamaIndex and the provider SDKs; tool-call argument inspection for agents. |
| 1.3 | Detection depth | Optional local NER model for names and addresses; language packs (EU national IDs, UK NINO, Indian Aadhaar/PAN); custom regex rules in policy packs. |
| 1.4 | Prompt operations | Prompt library with versions and lint history; A/B evaluation of rewrites against test inputs with an LLM judge from another model family, gated on measured agreement with people. |
| 1.5 | Enterprise | Postgres audit store, OIDC, per-team policies, SIEM export (CEF/OTLP), OpenTelemetry traces, Helm chart. |
| 1.6 | Browser | Extension that inspects what is pasted into AI chat sites, using the same API and policies. |

Each phase ships with tests, benchmark samples for any new detector, and an ADR for any new decision.
