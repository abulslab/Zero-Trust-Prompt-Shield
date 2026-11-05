"""Checks that turn a pattern match into a real finding (checksums, ranges, placeholders)."""

from __future__ import annotations

import ipaddress
import math
import re

_PLACEHOLDER = re.compile(
    r"^(?:x+|\*+|\.+|-+|<[^>]*>|\{\{?[^}]*\}?\}|\$\{[^}]*\}|%[A-Z_]+%|\[[^\]]*\]|"
    r"(?:your|my|the)[_-]?\w*|changeme|change[_-]me|placeholder|example|redacted|null|none|true|false|"
    r"secret|password|token|xxx\w*|todo|tbd|\*\*\*+)$",
    re.IGNORECASE,
)


_CODE_REFERENCE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")


def not_placeholder(value: str) -> bool:
    """`password = <your password>` documents a field; it does not leak one."""
    v = value.strip().strip("'\"`")
    if len(v) < 4:
        return False
    if _PLACEHOLDER.match(v):
        return False
    if v.startswith(("$", "%", "{", "<", "[", "os.environ", "process.env", "env(", "getenv")):
        return False
    if _CODE_REFERENCE.fullmatch(v):  # settings.api_key, self.config.token: a reference to a secret, not one
        return False
    return len(set(v.lower())) > 2


def luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban(value: str) -> bool:
    v = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(v) <= 34 or not v[:2].isalpha() or not v[2:4].isdigit():
        return False
    rearranged = v[4:] + v[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def us_ssn(value: str) -> bool:
    parts = re.split(r"[- ]", value)
    if len(parts) != 3:
        return False
    area, group, serial = parts
    if area in {"000", "666"} or area.startswith("9") or group == "00" or serial == "0000":
        return False
    return value not in {"123-45-6789", "078-05-1120"}


_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def not_synthetic_email(value: str) -> bool:
    return not value.strip().lower().endswith(".invalid")


def private_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if any(ip in net for net in _DOC_NETS):
        return False
    return bool(ip.is_private and not ip.is_loopback and not ip.is_unspecified and str(ip) != "0.0.0.0")


def phone(value: str) -> bool:
    v = value.strip()
    if re.fullmatch(r"\+44 20 7946 00\d\d", v):
        return False
    digits = re.sub(r"\D", "", v)
    if not 10 <= len(digits) <= 15 or len(set(digits)) <= 2:
        return False
    # Dates, versions and long numeric ids look like phone numbers; require a phone-like separator or a "+".
    return v.startswith("+") or bool(re.search(r"[\s().-]", v))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
