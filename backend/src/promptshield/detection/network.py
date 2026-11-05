"""Internal infrastructure: private addresses and internal host names."""

from __future__ import annotations

from promptshield.detection.base import PatternDetector, PatternRule
from promptshield.detection.validators import private_ipv4
from promptshield.domain import Category, Severity

_TOPOLOGY = "Replace internal addresses and host names with neutral labels (for example <<HOST_1>>); they map the internal network."

RULES: list[PatternRule] = [
    PatternRule(
        id="network.private_ip",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        title="Private IP address",
        message="An address from a private range reveals internal network layout.",
        guidance=_TOPOLOGY,
        pattern=r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        confidence=0.9,
        validator=private_ipv4,
    ),
    PatternRule(
        id="network.internal_host",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        title="Internal host name",
        message="A host name in an internal-only domain.",
        guidance=_TOPOLOGY,
        # DNS-shaped and bounded (labels of at most 63 characters, at most 10 of them) so that long runs of
        # letters, digits and dashes cannot make the engine backtrack quadratically.
        pattern=r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}(?:internal|intranet|corp|lan|local|localdomain|private|svc\.cluster\.local)\b(?![.-]\w)",
        confidence=0.8,
    ),
]


def detector() -> PatternDetector:
    return PatternDetector("network", RULES)
