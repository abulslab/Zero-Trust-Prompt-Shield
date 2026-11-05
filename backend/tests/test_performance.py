"""Hostile inputs must not make any detector backtrack quadratically (ReDoS).

A quadratic pattern turns a 50,000-character request into tens of seconds of CPU; a linear one stays well under a
second. The budget is generous so the test is stable on slow CI machines but still fails on a quadratic regression
(the internal-host rule took 98 s on 200,000 characters before it was bounded).
"""

from __future__ import annotations

import time

import pytest

from promptshield.domain import ContentType, Direction
from promptshield.service import InspectOptions, Shield

N = 50_000
BUDGET_S = 2.5
HOSTILE = {
    "digit runs": "1234-",
    "pem headers without end": "-----BEGIN " + "PRIVATE KEY-----\n",
    "html comment openers": "<!-- ignore ",
    "markdown images": "![a](http://x?",
    "dotted hosts": "a.",
    "jwt prefixes": "eyJ",
    "openai prefixes": "sk-",
    "azure key runs": "AccountKey=",
    "angle brackets": "<div ",
    "connection strings": "postgres://a:",
    "emails without tld": "a@b",
    "zero width": "\u200b",
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_input_is_inspected_in_linear_time(shield: Shield, name: str) -> None:
    unit = HOSTILE[name]
    text = (unit * (N // len(unit) + 1))[:N]
    started = time.perf_counter()
    shield.inspect(
        text, InspectOptions(direction=Direction.CONTEXT, content_type=ContentType.TEXT, ai="off", record=False)
    )
    elapsed = time.perf_counter() - started
    assert elapsed < BUDGET_S, f"{name}: {elapsed:.2f}s for {N} characters"
