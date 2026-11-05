# Changelog

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
