# Contributing

## Setup

```bash
python -m venv .venv && .venv/Scripts/activate   # source .venv/bin/activate on macOS/Linux
pip install -e ".[dev]"
cd web && npm install
```

## Checks (the same as CI)

```bash
ruff check backend && ruff format --check backend
mypy
pytest
promptshield benchmark
cd web && npm run lint && npx tsc --noEmit && npm run build
```

## Adding a detector rule

1. Add a `PatternRule` to the right module in `backend/src/promptshield/detection/` (or a class implementing `Detector`).
2. Add a validator if the format has a checksum or placeholder forms.
3. Add a positive test and a hard negative in `backend/tests/test_detectors.py`.
4. Add at least one positive and one negative sample to `backend/src/promptshield/eval/corpus.py`.
5. Never commit a credential-shaped literal: build test values at run time (see `tests/conftest.py` and `eval/corpus.py`).

## Principles

- Rules decide; models propose. Nothing a model says becomes a finding without verification.
- Never log, store or return a raw sensitive value.
- Every feature has a rules-only path.
- A new architectural decision gets an ADR in `docs/adr/`.

## Commits

Conventional commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`).
