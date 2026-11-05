# 2. The model never sees values the rules already found

Status: accepted

## Context
Sending a prompt to an external model to check whether it is safe to send to an external model would defeat the purpose
if the check itself leaked the credential or the card number.

## Decision
Before semantic review and prompt optimisation, every rule finding is replaced by a placeholder (`<<EMAIL_1>>`). The
reviewer verifies evidence against the redacted text and maps spans back to the original through the redaction's
segment table. The guard uses the same mechanism with a mapping shared across messages.

## Consequences
- AI review adds coverage without adding exposure for anything the rules recognise.
- Unknown secrets (no rule matches) can still reach the model; the entropy rule exists to narrow that gap, and the
  strict policy blocks on any secret-like value.
