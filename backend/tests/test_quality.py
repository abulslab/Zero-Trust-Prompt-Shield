from __future__ import annotations

import json

from conftest import shield_with
from promptshield.quality import lint
from promptshield.service import Shield


def test_vague_prompt_scores_low_and_good_prompt_scores_high() -> None:
    bad = lint("make it better and stuff etc")
    good = lint(
        "You are a senior QA engineer. Review the release notes below for a non-technical audience, because product "
        "managers will read them. Return a Markdown table with columns Change, Risk and Test needed, at most 10 rows.\n"
        "```\nfixed login timeout\n```"
    )
    assert bad.score < 70 and {"PQ001", "PQ003", "PQ006"} <= {i.id for i in bad.issues}
    assert good.score >= 85, [i.id for i in good.issues]


def test_conflicts_variables_and_dangling_references() -> None:
    r = lint("It should be brief but also detailed and comprehensive. Use {{customer_name}} and {product}.")
    ids = {i.id for i in r.issues}
    assert {"PQ008", "PQ013", "PQ014"} <= ids
    assert r.variables == ["{product}", "{{customer_name}}"]


def test_lint_counts_sensitive_data_against_safety(shield: Shield) -> None:
    report, _ = shield.lint("Summarise the complaint from user1@example.com in three bullet points for support.")
    assert any(i.id == "PQ100" for i in report.issues) and report.dimensions["safety"] < 100


def test_template_rewrite_without_a_model(shield: Shield) -> None:
    r = shield.optimizer.optimize("write some tests for everything in the login page")
    assert r.engine == "template" and all(c.passed for c in r.checks)
    assert r.after.score > r.before.score
    assert "write some tests for everything in the login page" in r.rewrite


def test_model_rewrite_is_kept_when_it_passes_checks() -> None:
    good = (
        "You are a QA engineer. Write 5 test cases for the login page of {{app}} for the team lead. "
        "Return a Markdown table with columns ID, Steps, Expected result. Contact: <<EMAIL_1>>."
    )
    shield, provider = shield_with([json.dumps({"rewrite": good, "changes": ["Added role", "Added format"]})])
    r = shield.optimizer.optimize("write tests for login of {{app}} and email user1@example.com")
    assert r.engine == "model", [c for c in r.checks if not c.passed]
    assert "user1@example.com" in r.rewrite and "<<EMAIL_1>>" in r.safe_rewrite
    assert "user1@example.com" not in provider.calls[0][1]


def test_model_rewrite_that_drops_a_variable_is_rejected() -> None:
    bad = "You are a QA engineer. Write 5 test cases for the login page. Return a Markdown table."
    shield, _ = shield_with([json.dumps({"rewrite": bad, "changes": []})])
    r = shield.optimizer.optimize("write tests for login of {{app}}")
    assert r.engine == "template" and r.rejected_model_rewrite and "Keeps variables" in (r.model_error or "")
