"""Audit trail and feedback, behind a small repository port (SQLite by default).

Zero trust applies to the shield itself: it stores a hash and the length of each text, the decision, and findings with
masked previews. It never stores the text or a raw sensitive value. Every inspection record is linked into a
tamper-evident SHA-256 hash chain (`prev_hash` -> `entry_hash`) so silent row modification or deletion is detectable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from promptshield.domain import InspectionResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS inspections (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  direction TEXT NOT NULL,
  content_type TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  action TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  length INTEGER NOT NULL,
  content_sha256 TEXT NOT NULL,
  finding_count INTEGER NOT NULL,
  ai_used INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  body TEXT NOT NULL,
  prev_hash TEXT NOT NULL DEFAULT 'GENESIS',
  entry_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_inspections_created ON inspections(created_at DESC);
CREATE TABLE IF NOT EXISTS feedback (
  fingerprint TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  note TEXT,
  preview TEXT,
  inspection_id TEXT,
  created_at TEXT NOT NULL
);
"""


def _compute_entry_hash(
    prev_hash: str,
    *,
    id: str,
    created_at: str,
    source: str,
    kind: str,
    direction: str,
    content_type: str,
    policy_id: str,
    action: str,
    risk_score: int,
    length: int,
    content_sha256: str,
    finding_count: int,
    ai_used: int,
    duration_ms: int,
    body: str,
) -> str:
    canonical = (
        f"{prev_hash}|{id}|{created_at}|{source}|{kind}|{direction}|{content_type}|"
        f"{policy_id}|{action}|{risk_score}|{length}|{content_sha256}|{finding_count}|{ai_used}|{duration_ms}|{body}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditStore(Protocol):
    def record(self, result: InspectionResult, *, source: str, kind: str) -> None: ...
    def recent(self, limit: int = 50, offset: int = 0, action: str | None = None) -> list[dict[str, Any]]: ...
    def get(self, inspection_id: str) -> dict[str, Any] | None: ...
    def stats(self) -> dict[str, Any]: ...
    def verify_chain(self) -> dict[str, Any]: ...
    def suppressed(self) -> set[str]: ...
    def add_feedback(
        self,
        fingerprint: str,
        rule_id: str,
        verdict: str,
        note: str | None,
        preview: str | None,
        inspection_id: str | None,
    ) -> None: ...
    def list_feedback(self) -> list[dict[str, Any]]: ...
    def delete_feedback(self, fingerprint: str) -> bool: ...


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class SqliteAuditStore:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            cols = {r[1] for r in self._db.execute("PRAGMA table_info(inspections)").fetchall()}
            if "prev_hash" not in cols:
                self._db.execute("ALTER TABLE inspections ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'GENESIS'")
            if "entry_hash" not in cols:
                self._db.execute("ALTER TABLE inspections ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''")
            self._db.commit()
            self._db.execute("PRAGMA journal_mode=WAL") if path != ":memory:" else None

    def record(self, result: InspectionResult, *, source: str, kind: str) -> None:
        body = result.public()
        body.pop("redacted", None)  # redacted text may still contain context; the audit keeps metadata only
        body_json = json.dumps(body, sort_keys=True)
        finding_count = sum(1 for f in result.findings if not f.suppressed)
        ai_used = int(result.ai.used)
        duration_ms = sum(result.timings_ms.values())
        with self._lock:
            last = self._db.execute("SELECT entry_hash FROM inspections ORDER BY rowid DESC LIMIT 1").fetchone()
            prev_hash = last["entry_hash"] if last and last["entry_hash"] else "GENESIS"
            entry_hash = _compute_entry_hash(
                prev_hash,
                id=result.id,
                created_at=result.created_at,
                source=source,
                kind=kind,
                direction=result.direction.value,
                content_type=result.content_type.value,
                policy_id=result.decision.policy_id,
                action=result.decision.action.value,
                risk_score=result.decision.risk_score,
                length=result.length,
                content_sha256=result.content_sha256,
                finding_count=finding_count,
                ai_used=ai_used,
                duration_ms=duration_ms,
                body=body_json,
            )
            self._db.execute(
                "INSERT OR REPLACE INTO inspections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result.id,
                    result.created_at,
                    source,
                    kind,
                    result.direction.value,
                    result.content_type.value,
                    result.decision.policy_id,
                    result.decision.action.value,
                    result.decision.risk_score,
                    result.length,
                    result.content_sha256,
                    finding_count,
                    ai_used,
                    duration_ms,
                    body_json,
                    prev_hash,
                    entry_hash,
                ),
            )
            self._db.commit()

    def recent(self, limit: int = 50, offset: int = 0, action: str | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT id, created_at, source, kind, direction, content_type, policy_id, action, risk_score, "
            "length, finding_count, ai_used, duration_ms, body, prev_hash, entry_hash FROM inspections"
        )
        args: list[Any] = []
        if action:
            sql += " WHERE action = ?"
            args.append(action)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            body = json.loads(d.pop("body"))
            d["counts"] = body.get("counts", {})
            d["summary"] = body.get("summary", "")
            d["ai_used"] = bool(d["ai_used"])
            out.append(d)
        return out

    def get(self, inspection_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self._db.execute(
                "SELECT source, kind, body, prev_hash, entry_hash FROM inspections WHERE id = ?", (inspection_id,)
            ).fetchone()
        if r is None:
            return None
        body: dict[str, Any] = json.loads(r["body"])
        body["source"], body["kind"] = r["source"], r["kind"]
        body["prev_hash"], body["entry_hash"] = r["prev_hash"], r["entry_hash"]
        return body

    def verify_chain(self) -> dict[str, Any]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, created_at, source, kind, direction, content_type, policy_id, action, risk_score, "
                "length, content_sha256, finding_count, ai_used, duration_ms, body, prev_hash, entry_hash "
                "FROM inspections ORDER BY rowid ASC"
            ).fetchall()
        expected_prev = "GENESIS"
        for idx, r in enumerate(rows):
            if r["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "checked": idx,
                    "total": len(rows),
                    "head_hash": expected_prev,
                    "broken_at": r["id"],
                    "reason": "prev_hash_mismatch",
                }
            computed = _compute_entry_hash(
                expected_prev,
                id=r["id"],
                created_at=r["created_at"],
                source=r["source"],
                kind=r["kind"],
                direction=r["direction"],
                content_type=r["content_type"],
                policy_id=r["policy_id"],
                action=r["action"],
                risk_score=r["risk_score"],
                length=r["length"],
                content_sha256=r["content_sha256"],
                finding_count=r["finding_count"],
                ai_used=r["ai_used"],
                duration_ms=r["duration_ms"],
                body=r["body"],
            )
            if r["entry_hash"] != computed:
                return {
                    "valid": False,
                    "checked": idx,
                    "total": len(rows),
                    "head_hash": expected_prev,
                    "broken_at": r["id"],
                    "reason": "entry_hash_mismatch",
                }
            expected_prev = r["entry_hash"]
        return {
            "valid": True,
            "checked": len(rows),
            "total": len(rows),
            "head_hash": expected_prev,
            "broken_at": None,
        }

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self._db.execute(
                "SELECT COUNT(*), COALESCE(AVG(risk_score),0), COALESCE(SUM(finding_count),0), COALESCE(SUM(ai_used),0) FROM inspections"
            ).fetchone()
            by_action = dict(self._db.execute("SELECT action, COUNT(*) FROM inspections GROUP BY action").fetchall())
            by_direction = dict(
                self._db.execute("SELECT direction, COUNT(*) FROM inspections GROUP BY direction").fetchall()
            )
            bodies = self._db.execute("SELECT body FROM inspections ORDER BY created_at DESC LIMIT 1000").fetchall()
            daily = self._db.execute(
                "SELECT substr(created_at,1,10) d, COUNT(*), SUM(action='block'), SUM(action='redact') FROM inspections "
                "GROUP BY d ORDER BY d DESC LIMIT 14"
            ).fetchall()
            fb = dict(self._db.execute("SELECT verdict, COUNT(*) FROM feedback GROUP BY verdict").fetchall())
        by_category: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for (b,) in bodies:
            body = json.loads(b)
            for k, v in body.get("counts", {}).items():
                by_category[k] = by_category.get(k, 0) + v
            for f in body.get("findings", []):
                if not f.get("suppressed"):
                    by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1
        chain = self.verify_chain()
        return {
            "inspections": total[0],
            "avg_risk": round(total[1], 1),
            "findings": total[2],
            "ai_reviews": total[3],
            "by_action": by_action,
            "by_direction": by_direction,
            "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "top_rules": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])[:10]),
            "daily": [
                {"date": d, "total": t, "blocked": bl or 0, "redacted": rd or 0} for d, t, bl, rd in reversed(daily)
            ],
            "feedback": fb,
            "chain": chain,
        }

    def suppressed(self) -> set[str]:
        with self._lock:
            return {r[0] for r in self._db.execute("SELECT fingerprint FROM feedback WHERE verdict = 'false_positive'")}

    def add_feedback(
        self,
        fingerprint: str,
        rule_id: str,
        verdict: str,
        note: str | None,
        preview: str | None,
        inspection_id: str | None,
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO feedback VALUES (?,?,?,?,?,?,?)",
                (fingerprint, rule_id, verdict, note, preview, inspection_id, now()),
            )
            self._db.commit()

    def list_feedback(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute("SELECT * FROM feedback ORDER BY created_at DESC")]

    def delete_feedback(self, fingerprint: str) -> bool:
        with self._lock:
            n = self._db.execute("DELETE FROM feedback WHERE fingerprint = ?", (fingerprint,)).rowcount
            self._db.commit()
        return n > 0
