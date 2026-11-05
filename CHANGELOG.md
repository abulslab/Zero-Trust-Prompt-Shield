# Changelog

## 1.0.1 (2026-11-05)

Hardening from live testing with a local model (Ollama `qwen2.5:7b`).

- Verifier: quotes that run over values the rules already handled are trimmed to what the model added; rule findings
  always win overlaps; "injection" proposals must address an AI; personal and customer data must name someone;
  credential quotes around an already-handled token are rejected.
- The model now sees a description of every review category.
- Gateway: 180-second default timeout for Ollama (30 for hosted providers) and one retry on server errors.
- Default local model is `qwen2.5:7b`; empty values in `.env` fall back to defaults instead of failing.
- UI: compact finding actions (Real, Dismiss), "PII" label, clearer optimiser and guard wording.
- README: screenshots, measured local-model results, provider setup.

## 1.0.0 (2026-11-05)

First release of the rebuilt platform (the earlier proof of concept is retired).

- Rule-based detectors for credentials, personal and financial data, internal infrastructure, confidentiality markers,
  restricted terms and random-looking tokens; diff-aware.
- Direction-aware injection and obfuscation defence (input, context, output).
- Verified AI review: redaction before the model, exact-span evidence, reported rejections.
- Reversible and one-way redaction; guarded chat gateway.
- Prompt linter (five dimensions, 16 checks) and checked optimiser.
- YAML policy packs: balanced, strict, developer, RAG ingestion.
- Audit trail without content; feedback-driven suppressions by fingerprint.
- REST API, CLI with SARIF, GitHub Action, pre-commit hook, web UI, labelled benchmark.
