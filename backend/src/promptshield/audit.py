"""Audit trail and feedback, behind a small repository port (SQLite by default).

Zero trust applies to the shield itself: it stores a hash and the length of each text, the decision, and findings with
masked previews. It never stores the text or a raw sensitive value.
"""

from __future__ import annotations

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
  body TEXT NOT NULL
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


class AuditStore(Protocol):
    def record(self, result: InspectionResult, *, source: str, kind: str) -> None: ...
    def recent(self, limit: int = 50, offset: int = 0, action: str | None = None) -> list[dict[str, Any]]: ...
    def get(self, inspection_id: str) -> dict[str, Any] | None: ...
    def stats(self) -> dict[str, Any]: ...
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
            self._db.execute("PRAGMA journal_mode=WAL") if path != ":memory:" else None

    def record(self, result: InspectionResult, *, source: str, kind: str) -> None:
        body = result.public()
        body.pop("redacted", None)  # redacted text may still contain context; the audit keeps metadata only
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO inspections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    sum(1 for f in result.findings if not f.suppressed),
                    int(result.ai.used),
                    sum(result.timings_ms.values()),
                    json.dumps(body),
                ),
            )
            self._db.commit()

    def recent(self, limit: int = 50, offset: int = 0, action: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT id, created_at, source, kind, direction, content_type, policy_id, action, risk_score, length, finding_count, ai_used, duration_ms, body FROM inspections"
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
            r = self._db.execute("SELECT source, kind, body FROM inspections WHERE id = ?", (inspection_id,)).fetchone()
        if r is None:
            return None
        body: dict[str, Any] = json.loads(r["body"])
        body["source"], body["kind"] = r["source"], r["kind"]
        return body

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
