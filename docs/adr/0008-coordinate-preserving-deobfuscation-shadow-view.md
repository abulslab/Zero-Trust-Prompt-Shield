# 8. Coordinate-preserving de-obfuscation shadow view

Status: accepted

## Context
Adversaries routinely bypass regex-based prompt-injection and confidentiality detectors by inserting invisible Unicode
controls (zero-width spaces, soft hyphens, bidi overrides, Unicode tag characters) in the middle of keywords or by
substituting visually identical Cyrillic, Greek or full-width Latin homoglyphs. Naively stripping or normalising the
input text before running detectors breaks character offsets, line/column spans and reversible redaction.

## Decision
`Document` builds a lazy/ASCII-short-circuited de-obfuscated shadow projection (`doc.normalized`) alongside an index map
(`_norm_to_orig`) whenever non-ASCII characters are present. Invisible format controls are stripped and confusable
homoglyphs are folded to their ASCII equivalents. `PatternDetector` scans `doc.text` first and, when obfuscation is
present, also runs injection, confidentiality and secret rules against `doc.normalized`, translating any matched shadow
span back to exact `[start, end)` character offsets in `doc.text`.

## Consequences
- Pure-ASCII inputs incur zero extra allocations (`text.isascii()` short-circuits in C).
- Obfuscated payloads are caught by the existing declarative rules without complicating regex patterns.
- Every finding still carries exact line, column and character offsets in the caller's original text.

