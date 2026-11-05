# 6. Prompt rewrites are checked before they are shown

Status: accepted

## Context
A model asked to improve a prompt may drop template variables, add facts, reintroduce redacted data or simply make it
worse. Showing an unchecked rewrite moves risk from the original prompt to the "improved" one.

## Decision
The optimiser sends the redacted prompt, then runs deterministic checks on the rewrite: every variable and placeholder
kept, no invented placeholders, no new sensitive findings or injections, lint score not lower, length within bounds.
A rewrite that fails any check is discarded with the reason, and a deterministic structured rewrite is returned instead.

## Consequences
- The feature works without a model and degrades safely with a weak one.
- The lint score is a heuristic, so "not lower" is a guard rail, not proof of quality.
