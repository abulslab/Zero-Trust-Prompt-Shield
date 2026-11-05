"""Shared fixtures. Credential-shaped test values are assembled at run time so the repository holds none."""

from __future__ import annotations

import pytest

from promptshield.ai import ModelGateway, ScriptedProvider
from promptshield.audit import SqliteAuditStore
from promptshield.policy import PolicyStore
from promptshield.service import Shield


def gh_token() -> str:
    return "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"


def openai_key() -> str:
    return "sk-" + "proj-" + "Zq8Lm2Nx7Pw4Rt6Yv1Bc3Df5Gh9Jk0Lm2Np4Qr"


@pytest.fixture
def shield() -> Shield:
    return Shield(PolicyStore(), ModelGateway(None), SqliteAuditStore(":memory:"))


def shield_with(replies: list[str]) -> tuple[Shield, ScriptedProvider]:
    provider = ScriptedProvider(replies)
    return Shield(PolicyStore(), ModelGateway(provider), SqliteAuditStore(":memory:")), provider
