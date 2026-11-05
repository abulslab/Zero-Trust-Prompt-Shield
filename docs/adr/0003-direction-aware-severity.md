# 3. Severity depends on where the text sits

Status: accepted

## Context
"Ignore previous instructions" typed by a user is a jailbreak attempt against their own session. The same sentence in a
retrieved web page is an attack on the user by a third party. Personal data in a prompt is the user's choice; in an
answer it may be a leak.

## Decision
Every inspection has a direction: input, context or output. Rules carry per-direction severities, and policy rules can
match on direction. The guard inspects tool and document messages as context, separately from the conversation.

## Consequences
- Indirect injection blocks by default while users can still discuss injection safely.
- Callers must say what the text is; the API defaults to input.
