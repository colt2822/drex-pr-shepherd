"""SQLite persistence. Events are append-only (enforced by triggers); the watched-PR row is a
derived aggregate that can be rebuilt from the event history."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import sqlite3
from typing import Any, Iterable, Iterator, Optional

from ..core.models import (
    CIState,
    EventType,
    MergeState,
    ReviewState,
    SettlementStage,
    ShepherdEvent,
    State,
    WatchedPR,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS watched_prs (
  shepherd_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, task_id TEXT NOT NULL,
  repository TEXT NOT NULL, pr_number INTEGER NOT NULL, pr_url TEXT NOT NULL,
  head_branch TEXT NOT NULL, head_sha TEXT NOT NULL, base_branch TEXT NOT NULL,
  state TEXT NOT NULL, last_seen_at REAL, last_event_at REAL,
  submission_artifact_digest TEXT, verification_receipt_id TEXT,
  ci_state TEXT, review_state TEXT, merge_state TEXT,
  review_round INTEGER, repair_round INTEGER, next_check_at REAL,
  backoff_state TEXT, created_at REAL, updated_at REAL,
  head_repository TEXT, settlement_stage TEXT, expected_payout TEXT, acceptance_contract TEXT,
  last_verification TEXT, known_shas TEXT, nonactionable_streak INTEGER, blocker TEXT, resume_state TEXT,
  UNIQUE(repository, pr_number)
);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, shepherd_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL, repository TEXT NOT NULL, pr_number INTEGER NOT NULL, actor TEXT,
  timestamp REAL, raw_ref TEXT, type TEXT NOT NULL, payload_digest TEXT NOT NULL, trust TEXT NOT NULL,
  payload TEXT NOT NULL,
  UNIQUE(shepherd_id, source_event_id)
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
CREATE TABLE IF NOT EXISTS transitions (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, shepherd_id TEXT NOT NULL, from_state TEXT, to_state TEXT,
  reason TEXT, event_id TEXT, at REAL
);
CREATE TABLE IF NOT EXISTS actions (
  action_key TEXT PRIMARY KEY, shepherd_id TEXT NOT NULL, route TEXT NOT NULL, kind TEXT,
  round_no INTEGER, status TEXT NOT NULL, payload TEXT, result TEXT, created_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS outbox (
  idem_key TEXT PRIMARY KEY, seq INTEGER UNIQUE, shepherd_id TEXT NOT NULL, target TEXT NOT NULL, op TEXT NOT NULL,
  payload TEXT NOT NULL, status TEXT NOT NULL, created_at REAL
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, level TEXT, kind TEXT, shepherd_id TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""

_JSON_FIELDS = {"backoff_state", "expected_payout", "acceptance_contract", "last_verification", "known_shas", "blocker"}
_ENUMS = {"state": State, "ci_state": CIState, "review_state": ReviewState, "merge_state": MergeState,
          "settlement_stage": SettlementStage}


def _dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


class Store:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._depth = 0

    def close(self) -> None:
        self.conn.close()

    @contextlib.contextmanager
    def tx(self) -> Iterator[None]:
        if self._depth:
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
            return
        self.conn.execute("BEGIN IMMEDIATE")
        self._depth = 1
        try:
            yield
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        finally:
            self._depth = 0

    # ---- watched PRs
    def save_pr(self, pr: WatchedPR) -> None:
        row = {}
        for f in dataclasses.fields(pr):
            v = getattr(pr, f.name)
            if f.name in _JSON_FIELDS:
                v = _dumps(v)
            elif f.name in _ENUMS:
                v = v.value
            row[f.name] = v
        cols = ",".join(row)
        marks = ",".join(f":{k}" for k in row)
        upd = ",".join(f"{k}=excluded.{k}" for k in row if k != "shepherd_id")
        self.conn.execute(
            f"INSERT INTO watched_prs ({cols}) VALUES ({marks}) ON CONFLICT(shepherd_id) DO UPDATE SET {upd}", row
        )

    def _pr(self, r: sqlite3.Row) -> WatchedPR:
        d = dict(r)
        for k in _JSON_FIELDS:
            d[k] = json.loads(d[k]) if d[k] is not None else None
        for k, enum_cls in _ENUMS.items():
            d[k] = enum_cls(d[k])
        d["backoff_state"] = d["backoff_state"] or {}
        d["acceptance_contract"] = d["acceptance_contract"] or {}
        d["last_verification"] = d["last_verification"] or {}
        d["known_shas"] = d["known_shas"] or []
        d["blocker"] = d["blocker"] or {}
        return WatchedPR(**d)

    def get_pr(self, shepherd_id: str) -> Optional[WatchedPR]:
        r = self.conn.execute("SELECT * FROM watched_prs WHERE shepherd_id=?", (shepherd_id,)).fetchone()
        return self._pr(r) if r else None

    def find_pr(self, repository: str, pr_number: int) -> Optional[WatchedPR]:
        r = self.conn.execute(
            "SELECT * FROM watched_prs WHERE lower(repository)=lower(?) AND pr_number=?", (repository, pr_number)
        ).fetchone()
        return self._pr(r) if r else None

    def list_prs(self) -> list[WatchedPR]:
        return [self._pr(r) for r in self.conn.execute("SELECT * FROM watched_prs ORDER BY created_at, shepherd_id")]

    # ---- events (append-only)
    def insert_event(self, ev: ShepherdEvent) -> Optional[ShepherdEvent]:
        """Returns the stored event, or None if this source event was already recorded."""
        try:
            cur = self.conn.execute(
                "INSERT INTO events (event_id, shepherd_id, source_event_id, repository, pr_number, actor, timestamp,"
                " raw_ref, type, payload_digest, trust, payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ev.event_id, ev.shepherd_id, ev.source_event_id, ev.repository, ev.pr_number, ev.actor, ev.timestamp,
                 ev.raw_ref, ev.type.value, ev.payload_digest, ev.trust, _dumps(ev.payload)),
            )
        except sqlite3.IntegrityError:
            return None
        return dataclasses.replace(ev, seq=cur.lastrowid)

    def _ev(self, r: sqlite3.Row) -> ShepherdEvent:
        return ShepherdEvent(
            event_id=r["event_id"], source_event_id=r["source_event_id"], shepherd_id=r["shepherd_id"],
            repository=r["repository"], pr_number=r["pr_number"], actor=r["actor"] or "", timestamp=r["timestamp"] or 0.0,
            raw_ref=r["raw_ref"] or "", type=EventType(r["type"]), payload_digest=r["payload_digest"],
            payload=json.loads(r["payload"]), trust=r["trust"], seq=r["seq"],
        )

    def events(self, shepherd_id: str, types: Optional[Iterable[EventType]] = None) -> list[ShepherdEvent]:
        rows = self.conn.execute("SELECT * FROM events WHERE shepherd_id=? ORDER BY seq", (shepherd_id,)).fetchall()
        evs = [self._ev(r) for r in rows]
        if types is not None:
            ts = set(types)
            evs = [e for e in evs if e.type in ts]
        return evs

    # ---- transitions / audit
    def log_transition(self, shepherd_id: str, frm: State, to: State, reason: str, event_id: str, at: float) -> None:
        self.conn.execute(
            "INSERT INTO transitions (shepherd_id, from_state, to_state, reason, event_id, at) VALUES (?,?,?,?,?,?)",
            (shepherd_id, frm.value, to.value, reason, event_id, at),
        )

    def transitions(self, shepherd_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM transitions WHERE shepherd_id=? ORDER BY seq", (shepherd_id,))]

    def audit(self, at: float, kind: str, shepherd_id: str = "", data: Optional[dict] = None, level: str = "info") -> None:
        self.conn.execute(
            "INSERT INTO audit (at, level, kind, shepherd_id, data) VALUES (?,?,?,?,?)",
            (at, level, kind, shepherd_id, _dumps(data or {})),
        )

    def audit_log(self, shepherd_id: str = "", kind: str = "") -> list[dict[str, Any]]:
        q, args = "SELECT * FROM audit WHERE 1=1", []
        if shepherd_id:
            q += " AND shepherd_id=?"; args.append(shepherd_id)
        if kind:
            q += " AND kind=?"; args.append(kind)
        out = []
        for r in self.conn.execute(q + " ORDER BY seq", args):
            d = dict(r); d["data"] = json.loads(d["data"]); out.append(d)
        return out

    # ---- actions (idempotent)
    def create_action(self, key: str, shepherd_id: str, route: str, kind: Optional[str], round_no: int,
                      payload: dict, status: str, now: float) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO actions (action_key, shepherd_id, route, kind, round_no, status, payload, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)", (key, shepherd_id, route, kind, round_no, status, _dumps(payload), now, now))
            return True
        except sqlite3.IntegrityError:
            return False

    def update_action(self, key: str, status: str, now: float, result: Optional[dict] = None) -> None:
        self.conn.execute("UPDATE actions SET status=?, result=COALESCE(?, result), updated_at=? WHERE action_key=?",
                          (status, _dumps(result) if result is not None else None, now, key))

    def _act(self, r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        d["payload"] = json.loads(d["payload"] or "{}")
        d["result"] = json.loads(d["result"]) if d["result"] else None
        return d

    def get_action(self, key: str) -> Optional[dict[str, Any]]:
        r = self.conn.execute("SELECT * FROM actions WHERE action_key=?", (key,)).fetchone()
        return self._act(r) if r else None

    def actions(self, shepherd_id: str, kind: Optional[str] = None, statuses: Optional[Iterable[str]] = None) -> list[dict[str, Any]]:
        rows = [self._act(r) for r in self.conn.execute(
            "SELECT * FROM actions WHERE shepherd_id=? ORDER BY created_at, rowid", (shepherd_id,))]
        if kind:
            rows = [r for r in rows if r["kind"] == kind]
        if statuses is not None:
            ss = set(statuses)
            rows = [r for r in rows if r["status"] in ss]
        return rows

    # ---- outbox (writes / outbound events; recorded before any live call)
    def enqueue_outbox(self, key: str, shepherd_id: str, target: str, op: str, payload: dict, status: str, now: float) -> bool:
        try:
            n = self.conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM outbox").fetchone()[0]
            self.conn.execute(
                "INSERT INTO outbox (idem_key, seq, shepherd_id, target, op, payload, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (key, n, shepherd_id, target, op, _dumps(payload), status, now))
            return True
        except sqlite3.IntegrityError:
            return False

    def get_outbox(self, key: str) -> Optional[dict[str, Any]]:
        r = self.conn.execute("SELECT * FROM outbox WHERE idem_key=?", (key,)).fetchone()
        if not r:
            return None
        d = dict(r); d["payload"] = json.loads(d["payload"]); return d

    def set_outbox_status(self, key: str, status: str) -> None:
        self.conn.execute("UPDATE outbox SET status=? WHERE idem_key=?", (status, key))

    def outbox(self, shepherd_id: str = "", target: str = "") -> list[dict[str, Any]]:
        q, args = "SELECT * FROM outbox WHERE 1=1", []
        if shepherd_id:
            q += " AND shepherd_id=?"; args.append(shepherd_id)
        if target:
            q += " AND target=?"; args.append(target)
        out = []
        for r in self.conn.execute(q + " ORDER BY seq", args):
            d = dict(r); d["payload"] = json.loads(d["payload"]); out.append(d)
        return out

    # ---- kv
    def kv_get(self, k: str, default: Any = None) -> Any:
        r = self.conn.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r["v"]) if r else default

    def kv_set(self, k: str, v: Any) -> None:
        self.conn.execute("INSERT INTO kv (k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, _dumps(v)))
