# 10. Tamper-evident audit hash chain, HMAC fingerprints and synthetic redaction

Status: accepted

## Context
1. An audit database that stores no raw text still needs integrity: if an attacker or insider deletes or edits an
   inspection row in SQLite to hide a blocked exfiltration attempt, operators should be able to prove the log was
   tampered with.
2. Plain SHA-256 fingerprints (`sha256(rule_id + "\0" + value)`) of low-entropy values such as phone numbers, 9-digit
   SSNs or private IPv4 addresses can be brute-forced offline with a rainbow table.
3. Bracketed placeholders (`<<EMAIL_1>>`) work well for prose prompts, but break downstream tools or code paths that
   validate email, IP, phone or hostname syntax.

## Decision
1. **Tamper-evident audit chain**: Each inspection row in `SqliteAuditStore` stores `prev_hash` and `entry_hash`, where
   `entry_hash = sha256(prev_hash | canonical_row_fields)`. `GET /v1/audit/verify` and `promptshield audit-verify`
   recompute the chain from `GENESIS` and report the exact inspection id if any row was modified or removed.
2. **HMAC-keyed fingerprints**: When `SHIELD_FINGERPRINT_KEY` is set, `fingerprint()` uses `HMAC-SHA256` instead of
   unkeyed `SHA-256`, preventing offline dictionary attacks against low-entropy identifiers.
3. **Format-preserving synthetic redaction (`RedactionMode.SYNTHETIC`)**: Replaces emails, phones, SSNs, private IPs,
   hosts and cards with deterministic RFC-reserved surrogates (`user1@redacted.invalid`, `192.0.2.1`,
   `+44 20 7946 0001`) while keeping the mapping reversible through `restore()`.

## Consequences
- Audit integrity is verifiable via API, CLI and UI without external infrastructure.
- Operators can harden fingerprints with a single environment variable (`SHIELD_FINGERPRINT_KEY`).
- Callers can choose `placeholder`, `synthetic` or `mask` redaction per request.

