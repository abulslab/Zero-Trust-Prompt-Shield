"""Command line: scan files, diffs or stdin in CI and pre-commit hooks; lint prompts; run the server.

Exit codes: 0 clean (below --fail-on), 1 findings at or above --fail-on, 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from promptshield import __version__
from promptshield.ai import ModelGateway, build_gateway
from promptshield.config import get_settings
from promptshield.domain import Action, ContentType, Direction, InspectionResult
from promptshield.policy import PolicyStore
from promptshield.redaction import RedactionMode
from promptshield.service import InspectOptions, Shield

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_TEXT_EXT = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".prompt",
    ".env",
    ".cfg",
    ".ini",
    ".toml",
    ".cs",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".sh",
    ".ps1",
    ".sql",
    ".xml",
    ".html",
    ".tf",
    ".j2",
    ".jinja",
    ".mustache",
    ".hbs",
    ".properties",
    ".conf",
    "",
}


# Generated lockfiles are huge, full of hashes, and never hold hand-written secrets.
_SKIP_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    "packages.lock.json",
}


def _shield(policy_dir: str | None, ai: bool) -> Shield:
    s = get_settings()
    gateway = build_gateway(s) if ai else ModelGateway(None)
    return Shield(
        PolicyStore(policy_dir or s.policy_dir),
        gateway,
        audit=None,
        default_policy=s.default_policy,
        max_chars=s.max_chars,
    )


def _targets(args: argparse.Namespace) -> list[tuple[str, str, ContentType]]:
    if args.diff is not None:
        cmd = ["git", "diff", "--unified=0", "--no-color"] + ([args.diff] if args.diff else ["--cached"])
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        return _split_diff(out)
    if not args.paths or args.paths == ["-"]:
        return [("<stdin>", sys.stdin.read(), ContentType(args.content_type))]
    items: list[tuple[str, str, ContentType]] = []
    for p in args.paths:
        path = Path(p)
        files = [f for f in path.rglob("*") if f.is_file()] if path.is_dir() else [path]
        for f in files:
            if any(part in {".git", "node_modules", ".venv", "dist", ".next", "__pycache__"} for part in f.parts):
                continue
            if f.suffix.lower() not in _TEXT_EXT or f.stat().st_size > 2_000_000:
                continue
            try:
                items.append((str(f), f.read_text(encoding="utf-8"), ContentType(args.content_type)))
            except (UnicodeDecodeError, OSError):
                continue
    return items


def _split_diff(diff: str) -> list[tuple[str, str, ContentType]]:
    files: list[tuple[str, str, ContentType]] = []
    name, buf = None, []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if name:
                files.append((name, "".join(buf), ContentType.DIFF))
            name, buf = line.split(" b/", 1)[-1].strip(), [line]
        else:
            buf.append(line)
    if name:
        files.append((name, "".join(buf), ContentType.DIFF))
    return files


def _diff_line_map(text: str) -> dict[int, int]:
    """Map a line of the diff text to the line number in the new file, for annotations."""
    mapping: dict[int, int] = {}
    new_line = 0
    for i, line in enumerate(text.splitlines(), start=1):
        if line.startswith("@@"):
            try:
                new_line = int(line.split("+", 1)[1].split(",")[0].split(" ")[0]) - 1
            except (IndexError, ValueError):
                new_line = 0
        elif line.startswith("+") and not line.startswith("+++"):
            new_line += 1
            mapping[i] = new_line
        elif not line.startswith("-"):
            new_line += 1
    return mapping


def cmd_scan(args: argparse.Namespace) -> int:
    shield = _shield(args.policy_dir, args.ai)
    results: list[tuple[str, InspectionResult, dict[int, int]]] = []
    for name, text, ctype in _targets(args):
        if Path(name).name in _SKIP_FILES:
            continue
        if len(text) > shield.max_chars:
            # One huge file must not hide findings in the others; say so and move on.
            print(f"promptshield: skipped {name} ({len(text)} characters, limit {shield.max_chars})", file=sys.stderr)
            continue
        r = shield.inspect(
            text,
            InspectOptions(
                direction=Direction(args.direction),
                content_type=ctype,
                policy_id=args.policy,
                ai="on" if args.ai else "off",
                record=False,
                source="cli",
            ),
        )
        results.append((name, r, _diff_line_map(text) if ctype == ContentType.DIFF else {}))

    fail_rank = Action(args.fail_on).rank
    failed = any(r.decision.action.rank >= fail_rank for _, r, _ in results)
    if args.format == "json":
        print(json.dumps([{"file": n, **r.public()} for n, r, _ in results], indent=2))
    elif args.format == "sarif":
        print(json.dumps(_sarif(results), indent=2))
    else:
        total = 0
        for name, r, lines in results:
            active = [f for f in r.findings if not f.suppressed]
            if not active:
                continue
            print(f"\n{name}  [{r.decision.action.value.upper()} | risk {r.decision.risk_score}]")
            for f in active:
                line = lines.get(f.span.line, f.span.line)
                print(f"  {line}:{f.span.column}  {f.severity.value:<8} {f.action.value:<6} {f.title}  ({f.rule_id})")
                total += 1
        print(
            f"\n{len(results)} file(s) scanned, {total} finding(s). "
            f"{'FAILED' if failed else 'passed'} (fail-on: {args.fail_on})."
        )
    return 1 if failed else 0


def _sarif(results: list[tuple[str, InspectionResult, dict[int, int]]]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    for name, r, lines in results:
        for f in r.findings:
            if f.suppressed:
                continue
            rules.setdefault(
                f.rule_id,
                {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "help": {"text": f.guidance},
                    "properties": {"category": f.category.value, "tags": f.tags},
                },
            )
            out.append(
                {
                    "ruleId": f.rule_id,
                    "level": _SARIF_LEVEL[f.severity.value],
                    "message": {"text": f"{f.message} Policy action: {f.action.value}."},
                    "partialFingerprints": {"promptshield/v1": f.fingerprint},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": name.replace("\\", "/")},
                                "region": {
                                    "startLine": lines.get(f.span.line, f.span.line),
                                    "startColumn": f.span.column,
                                },
                            }
                        }
                    ],
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Zero-Trust Prompt Shield",
                        "version": __version__,
                        "informationUri": "https://github.com/abulslab/Zero-Trust-Prompt-Shield",
                        "rules": list(rules.values()),
                    }
                },
                "results": out,
            }
        ],
    }


def cmd_lint(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(encoding="utf-8")
    report, _ = _shield(None, False).lint(text)
    if args.format == "json":
        print(json.dumps({**report.__dict__, "issues": [i.__dict__ for i in report.issues]}, indent=2))
    else:
        print(
            f"Prompt score {report.score}/100 (grade {report.grade})  "
            + "  ".join(f"{k} {v}" for k, v in report.dimensions.items())
        )
        for i in report.issues:
            print(f"  [{i.severity}] {i.id} {i.title}: {i.message}\n      fix: {i.suggestion}")
    return 1 if report.score < args.min_score else 0


def cmd_redact(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(encoding="utf-8")
    _, red = _shield(args.policy_dir, False).redact(
        text, InspectOptions(policy_id=args.policy, ai="off", record=False, redaction=RedactionMode(args.mode))
    )
    sys.stdout.write(red.text)
    if args.mapping:
        Path(args.mapping).write_text(json.dumps(red.mapping, indent=2), encoding="utf-8")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("promptshield.api.app:app_factory", factory=True, host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_benchmark(_: argparse.Namespace) -> int:
    from promptshield.eval.runner import run

    report = run(_shield(None, False)).public()
    print(json.dumps(report, indent=2))
    return 0 if report["overall"]["fn"] == 0 else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="promptshield", description="Zero-Trust Prompt Shield")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="Scan files, a git diff or stdin for secrets, personal data and injections.")
    sc.add_argument("paths", nargs="*", help="Files or folders; '-' or nothing reads stdin.")
    sc.add_argument(
        "--diff",
        nargs="?",
        const="",
        default=None,
        metavar="REF",
        help="Scan only added lines of `git diff REF` (staged changes when REF is omitted).",
    )
    sc.add_argument("--content-type", default="text", choices=[c.value for c in ContentType])
    sc.add_argument("--direction", default="input", choices=[d.value for d in Direction])
    sc.add_argument("--policy", default=None)
    sc.add_argument("--policy-dir", default=None)
    sc.add_argument("--ai", action="store_true", help="Also run semantic review with the configured model.")
    sc.add_argument("--format", default="text", choices=["text", "json", "sarif"])
    sc.add_argument("--fail-on", default="block", choices=[a.value for a in Action])
    sc.set_defaults(fn=cmd_scan)

    li = sub.add_parser("lint", help="Score a prompt and list fixes.")
    li.add_argument("path", nargs="?", default="-")
    li.add_argument("--format", default="text", choices=["text", "json"])
    li.add_argument("--min-score", type=int, default=0)
    li.set_defaults(fn=cmd_lint)

    rd = sub.add_parser("redact", help="Print the text with findings replaced.")
    rd.add_argument("path", nargs="?", default="-")
    rd.add_argument("--mode", default="placeholder", choices=[m.value for m in RedactionMode])
    rd.add_argument("--mapping", help="Write the placeholder mapping to this file (keep it private).")
    rd.add_argument("--policy", default=None)
    rd.add_argument("--policy-dir", default=None)
    rd.set_defaults(fn=cmd_redact)

    sv = sub.add_parser("serve", help="Run the HTTP API.")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=5380)
    sv.add_argument("--reload", action="store_true")
    sv.set_defaults(fn=cmd_serve)

    bm = sub.add_parser("benchmark", help="Measure the detectors on the built-in labelled corpus.")
    bm.set_defaults(fn=cmd_benchmark)

    args = p.parse_args(argv)
    try:
        return int(args.fn(args))
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError, ValueError) as e:
        print(f"promptshield: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
