# 1. The AI proposes, the engine verifies

Status: accepted

## Context
Models find things patterns cannot (a customer's name, an internal threshold described in prose), but they also
paraphrase, invent evidence and can be steered by the text they read. A security control that reports invented
findings, or misses real ones because a model was talked out of them, cannot be trusted.

## Decision
Rule-based detectors are the authority. A model may only propose findings. A proposal is kept only if its category is
in a fixed taxonomy, its confidence is at least 0.55 and its evidence is an exact span of the text the model saw
(whitespace-tolerant, otherwise character for character). Every rejected proposal is reported with the reason.

## Consequences
- Findings always point at real characters; the UI highlights them without re-searching.
- A model failure or refusal never removes a rule finding; the pipeline falls back to rules only.
- Model recall is limited to what it can quote exactly, which is the right trade-off for a control.
