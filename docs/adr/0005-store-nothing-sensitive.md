# 5. The shield stores nothing it protects

Status: accepted

## Context
An audit trail is required to show what was blocked and why. Storing the inspected text would turn the shield into the
most valuable target in the system.

## Decision
The audit store keeps a SHA-256 of each text, its length, the decision, timings and findings with masked previews.
Raw values are excluded at the domain layer (`Finding.value` is never serialised). Redaction mappings go back to the
caller and are never written. Feedback is keyed by a fingerprint (hash of rule id and value), so a false positive can be
suppressed without keeping the value. Logs carry no content.

## Consequences
- An auditor can prove a given text was inspected (by hashing it) without the log revealing it.
- Lost mappings cannot be recovered from the server, by design.
