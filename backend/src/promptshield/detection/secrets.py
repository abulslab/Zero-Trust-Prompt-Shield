"""Credentials, keys and tokens. Provider-specific formats first; generic assignments last with placeholder checks."""

from __future__ import annotations

import re

from promptshield.detection.base import PatternDetector, PatternRule
from promptshield.detection.validators import not_placeholder
from promptshield.domain import Category, Severity

_ROTATE = "Remove it from the text, revoke or rotate it with the issuer, and reference it by name (for example an environment variable) instead."


def _key(
    id_: str,
    title: str,
    pattern: str,
    severity: Severity = Severity.CRITICAL,
    confidence: float = 0.97,
    group: str | int = 0,
    flags: int = 0,
) -> PatternRule:
    return PatternRule(
        id=f"secret.{id_}",
        category=Category.SECRET,
        severity=severity,
        title=title,
        message=f"{title} found. Anyone who reads this text can use it.",
        guidance=_ROTATE,
        pattern=pattern,
        group=group,
        confidence=confidence,
        flags=flags,
        tags=("credential",),
    )


RULES: list[PatternRule] = [
    _key(
        "private_key",
        "Private key",
        r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{1,8192}?-----END (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----",
    ),
    _key("aws_access_key", "AWS access key ID", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b", Severity.HIGH),
    _key(
        "aws_secret_key",
        "AWS secret access key",
        r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?[:=]\s*['\"]?(?P<v>[A-Za-z0-9/+=]{40})\b",
        group="v",
    ),
    _key("github_token", "GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
    _key("gitlab_token", "GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,255}\b"),
    _key("slack_token", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"),
    _key(
        "slack_webhook",
        "Slack webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        Severity.HIGH,
    ),
    _key("stripe_key", "Stripe secret key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b"),
    _key("google_api_key", "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", Severity.HIGH),
    _key("anthropic_key", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,255}\b"),
    _key(
        "openai_key",
        "OpenAI API key",
        r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,255}\b",
        Severity.CRITICAL,
        0.9,
    ),
    _key("npm_token", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _key("azure_storage_key", "Azure storage account key", r"(?i)AccountKey=(?P<v>[A-Za-z0-9+/=]{60,128})", group="v"),
    _key("sendgrid_key", "SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{16,128}\.[A-Za-z0-9_-]{16,128}\b"),
    _key("twilio_key", "Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", Severity.HIGH, 0.8),
    _key(
        "jwt",
        "JSON Web Token",
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}\b",
        Severity.HIGH,
        0.95,
    ),
    _key(
        "bearer",
        "Bearer token in a header",
        r"(?i)\bauthorization\s*:\s*bearer\s+(?P<v>[A-Za-z0-9._~+/=-]{16,4096})",
        Severity.HIGH,
        0.9,
        group="v",
    ),
    _key(
        "basic_auth",
        "Basic authentication header",
        r"(?i)\bauthorization\s*:\s*basic\s+(?P<v>[A-Za-z0-9+/=]{12,1024})",
        Severity.HIGH,
        0.9,
        group="v",
    ),
    PatternRule(
        id="secret.connection_string",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        title="Connection string with a password",
        message="A database or broker connection string carries its password in clear text.",
        guidance="Remove the credentials from the URL and load them from a secret store; rotate the password if it was shared.",
        pattern=r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:@/]{1,256}:(?P<v>[^\s@/]{1,256})@[^\s'\"]{1,2048}",
        group="v",
        confidence=0.95,
        validator=not_placeholder,
        tags=("credential",),
    ),
    PatternRule(
        id="secret.url_credentials",
        category=Category.SECRET,
        severity=Severity.HIGH,
        title="Password embedded in a URL",
        message="The URL carries a user name and password.",
        guidance="Strip the credentials from the URL before sharing it.",
        pattern=r"\bhttps?://[^\s:@/]{1,256}:(?P<v>[^\s@/]{3,256})@[^\s'\"]{1,2048}",
        group="v",
        confidence=0.85,
        validator=not_placeholder,
        tags=("credential",),
    ),
    PatternRule(
        id="secret.password_assignment",
        category=Category.SECRET,
        severity=Severity.HIGH,
        title="Password in an assignment",
        message="A password or passphrase appears to be assigned a literal value.",
        guidance=_ROTATE,
        pattern=r"""(?i)\b(?:password|passwd|pwd|passphrase|pass)\b["']?\s*(?:[:=]|=>|:=|\bis\b)\s*(?P<q>["'`]?)(?P<v>[^\s"'`,;]{4,256})(?P=q)""",
        group="v",
        confidence=0.85,
        validator=not_placeholder,
        tags=("credential",),
    ),
    PatternRule(
        id="secret.generic_assignment",
        category=Category.SECRET,
        severity=Severity.HIGH,
        title="Secret-like value in an assignment",
        message="A value is assigned to a name that usually holds a secret (api key, token, client secret...).",
        guidance=_ROTATE,
        pattern=r"""(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|secret)\b["']?\s*(?:[:=]|=>|:=)\s*(?P<q>["'`]?)(?P<v>[A-Za-z0-9_\-+/=.]{12,512})(?P=q)""",
        group="v",
        confidence=0.8,
        validator=not_placeholder,
        tags=("credential",),
    ),
]


def detector() -> PatternDetector:
    return PatternDetector("secrets", RULES)


# Rules used by other components to tell whether a value is a known credential format.
KNOWN_FORMATS = [
    re.compile(r.pattern, r.flags)
    for r in RULES
    if r.id not in {"secret.password_assignment", "secret.generic_assignment"}
]
