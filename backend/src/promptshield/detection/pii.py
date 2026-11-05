"""Personal and financial data, with checksums where the format has one."""

from __future__ import annotations

from promptshield.detection.base import PatternDetector, PatternRule
from promptshield.detection.validators import iban, luhn, not_synthetic_email, phone, us_ssn
from promptshield.domain import Category, Direction, Severity

_PSEUDONYMISE = "Replace it with a placeholder (for example <<EMAIL_1>>) before sending; Prompt Shield can restore it in the answer."

RULES: list[PatternRule] = [
    PatternRule(
        id="pii.email",
        category=Category.PII,
        severity=Severity.MEDIUM,
        title="Email address",
        message="An email address identifies a person or a mailbox.",
        guidance=_PSEUDONYMISE,
        pattern=r"(?<![\w.+:/%-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b",
        confidence=0.95,
        validator=not_synthetic_email,
        tags=("gdpr",),
    ),
    PatternRule(
        id="pii.phone",
        category=Category.PII,
        severity=Severity.MEDIUM,
        title="Phone number",
        message="A phone number identifies a person.",
        guidance=_PSEUDONYMISE,
        # International form: a leading "+" is a strong signal on its own.
        pattern=r"(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{1,4}(?:[\s.-]?\d{2,4}){2,4}\b",
        confidence=0.8,
        validator=phone,
        tags=("gdpr",),
    ),
    PatternRule(
        id="pii.phone",
        category=Category.PII,
        severity=Severity.MEDIUM,
        title="Phone number",
        message="A phone number identifies a person.",
        guidance=_PSEUDONYMISE,
        # National form only next to a word that says it is a phone number: order ids and dates look the same.
        pattern=r"(?i)\b(?:call|phone|tel|telephone|mobile|cell|contact|whatsapp|fax|ring|text)\b[^\d\n]{0,25}"
        r"(?P<v>\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4})\b",
        group="v",
        confidence=0.75,
        validator=phone,
        tags=("gdpr",),
    ),
    PatternRule(
        id="pii.us_ssn",
        category=Category.PII,
        severity=Severity.HIGH,
        title="US Social Security number",
        message="A Social Security number is a government identifier.",
        guidance="Remove it. Government identifiers should never be sent to a model.",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        confidence=0.85,
        validator=us_ssn,
        tags=("gdpr", "government-id"),
    ),
    PatternRule(
        id="financial.card_number",
        category=Category.FINANCIAL,
        severity=Severity.CRITICAL,
        title="Payment card number",
        message="A number that passes the Luhn check and has a card number's length.",
        guidance="Remove it. Card numbers are in PCI DSS scope and must not leave the cardholder data environment.",
        pattern=r"\b(?:\d[ -]?){12,18}\d\b",
        confidence=0.9,
        validator=luhn,
        tags=("pci-dss",),
    ),
    PatternRule(
        id="financial.iban",
        category=Category.FINANCIAL,
        severity=Severity.HIGH,
        title="Bank account number (IBAN)",
        message="An IBAN with a valid checksum.",
        guidance=_PSEUDONYMISE,
        pattern=r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b",
        confidence=0.95,
        validator=iban,
        tags=("gdpr",),
    ),
]

# A model answering with personal data the user never gave is a leak; in a prompt it is the user's own choice.
for _r in RULES:
    _r.severity_by_direction.setdefault(
        Direction.OUTPUT, Severity.HIGH if _r.severity != Severity.CRITICAL else Severity.CRITICAL
    )


def detector() -> PatternDetector:
    return PatternDetector("pii", RULES)
