# 4. Policy as code

Status: accepted

## Context
What to do about a finding differs by organisation, data class and destination: a coding assistant on a local model and
a regulated workload on an external provider need different answers for the same email address.

## Decision
Decisions come from versionable YAML policy packs: detectors to run, restricted terms, an ordered list of rules (match
on category, direction, rule-id prefix, severity, confidence, origin) and a risk threshold. The engine applies the first
matching rule per finding and takes the most restrictive action overall.

## Consequences
- Security teams change behaviour without code changes and review policies like code.
- Four packs ship built in; custom packs load from SHIELD_POLICY_DIR.
