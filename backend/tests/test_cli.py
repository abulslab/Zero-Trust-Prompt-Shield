from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from conftest import gh_token
from promptshield.cli import _diff_line_map, main


def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stdin: str, *args: str) -> tuple[int, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = main(list(args))
    return code, capsys.readouterr().out


def test_scan_stdin_fails_on_secret(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(monkeypatch, capsys, f"token {gh_token()}", "scan")
    assert code == 1 and "secret.github_token" in out and gh_token() not in out


def test_scan_clean_passes(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = run(monkeypatch, capsys, "nothing to see", "scan")
    assert code == 0


def test_scan_sarif(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(monkeypatch, capsys, "mail user1@example.com", "scan", "--format", "sarif", "--fail-on", "redact")
    sarif = json.loads(out)
    assert code == 1 and sarif["runs"][0]["results"][0]["ruleId"] == "pii.email"


def test_lint_and_redact(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(monkeypatch, capsys, "make it better", "lint", "--min-score", "90")
    assert code == 1 and "PQ001" in out
    code, out = run(monkeypatch, capsys, "Ask user1@example.com", "redact")
    assert code == 0 and out == "Ask <<EMAIL_1>>"


def test_oversized_and_lock_files_are_skipped_not_fatal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "package-lock.json").write_text('{"password": "Winter2026!Blue"}', encoding="utf-8")
    (tmp_path / "big.txt").write_text("x" * 250_000, encoding="utf-8")
    (tmp_path / "leak.txt").write_text(f"token {gh_token()}", encoding="utf-8")
    code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()
    assert code == 1 and "secret.github_token" in captured.out
    assert "skipped" in captured.err and "big.txt" in captured.err and "package-lock" not in captured.out


def test_diff_line_map_points_at_new_file_lines() -> None:
    diff = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -10,0 +11,2 @@\n+a\n+b\n"
    assert _diff_line_map(diff) == {5: 11, 6: 12}


def test_diff_ref_that_looks_like_an_option_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--diff=--output=pwned.txt"]) == 2
    assert "expects a git ref" in capsys.readouterr().err
