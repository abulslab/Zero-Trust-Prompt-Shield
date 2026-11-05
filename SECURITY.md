# Security policy

Prompt Shield is a security control, so bypasses matter as much as crashes.

## Reporting

Please report vulnerabilities privately through GitHub's **Report a vulnerability** (Security tab → Advisories).
Do not open a public issue. Include a minimal input that reproduces the problem; use fake credentials and data.

In scope:
- A credential, personal-data or injection pattern that a built-in rule should catch but misses (detection bypass).
- Any path by which the shield stores, logs or returns a raw sensitive value.
- AI review or optimisation accepting a model proposal that fails the verifier's rules.
- Authentication, rate-limit or input-size bypasses in the API.

Expect an acknowledgement within five working days. Fixes ship with a regression test and, for detection bypasses, a
new benchmark sample.

## Supported versions

The latest release on `main`.
