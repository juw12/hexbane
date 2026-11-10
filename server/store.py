"""SQLite persistence for the Gardu chat gate: decision log, admin feedback, learned examples."""

import json
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    user TEXT NOT NULL,
    message TEXT NOT NULL,
    action TEXT NOT NULL,
    label TEXT NOT NULL,
    uncertain INTEGER NOT NULL,
    reason TEXT,
    scores TEXT,
    cost_saved REAL DEFAULT 0,
    reviewed_label TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS learned (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    text TEXT NOT NULL,
    ts REAL NOT NULL
);
"""

OFF_MISSION_ACTIONS = ("REDIRECT", "THROTTLE", "BLOCK")


class Store:
    def __init__(self, path: Path):
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.connection.executescript(SCHEMA)
            self.connection.commit()

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def log(self, user: str, message: str, decision) -> int:
        with self.lock:
            cursor = self.connection.execute(
                "INSERT INTO events (ts, user, message, action, label, uncertain, reason, scores, cost_saved) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    time.time(), user, message[:2000], decision.action, decision.label,
                    int(decision.uncertain), decision.reason, json.dumps(decision.scores),
                    decision.est_cost_saved_usd,
                ),
            )
            self.connection.commit()
            return cursor.lastrowid

    def add_feedback(self, event_id: int, label: str) -> str:
        """Admin correction. Returns the event message (now a learned example)."""
        with self.lock:
            row = self.connection.execute("SELECT message FROM events WHERE id = ?", (event_id,)).fetchone()
            if row is None:
                raise KeyError(event_id)
            self.connection.execute("UPDATE events SET reviewed_label = ? WHERE id = ?", (label, event_id))
            self.connection.execute(
                "INSERT INTO learned (label, text, ts) VALUES (?, ?, ?)", (label, row["message"], time.time())
            )
            self.connection.commit()
            return row["message"]

    def learned_examples(self) -> list[tuple[str, str]]:
        with self.lock:
            rows = self.connection.execute("SELECT label, text FROM learned ORDER BY id").fetchall()
        return [(row["label"], row["text"]) for row in rows]

    def _rows(self, sql: str, params: tuple = ()) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.connection.execute(sql, params).fetchall()]

    def stats(self, engine) -> dict:
        totals = self._rows("SELECT action, COUNT(*) AS n, SUM(cost_saved) AS saved FROM events GROUP BY action")
        action_counts = {row["action"]: row["n"] for row in totals}
        total = sum(action_counts.values())
        off_mission = sum(action_counts.get(action, 0) for action in OFF_MISSION_ACTIONS)
        cost_saved = sum(row["saved"] or 0 for row in totals)

        off_messages = [
            row["message"] for row in self._rows(
                "SELECT message FROM events WHERE action IN ('REDIRECT', 'THROTTLE') "
                "ORDER BY id DESC LIMIT 500"
            )
        ]
        flagged = self._rows(
            "SELECT user, COUNT(*) AS n, GROUP_CONCAT(DISTINCT action) AS actions FROM events "
            "WHERE action IN ('BLOCK', 'THROTTLE') GROUP BY user ORDER BY n DESC LIMIT 20"
        )
        review_queue = self._rows(
            "SELECT id, ts, user, message, action, label, reason FROM events "
            "WHERE reviewed_label IS NULL AND (uncertain = 1 OR action IN ('REDIRECT', 'THROTTLE')) "
            "ORDER BY id DESC LIMIT 25"
        )
        recent = self._rows(
            "SELECT id, ts, user, message, action, label, uncertain, reason FROM events ORDER BY id DESC LIMIT 30"
        )
        reviewed = self._rows(
            "SELECT label, reviewed_label FROM events WHERE reviewed_label IS NOT NULL"
        )
        corrections = Counter(
            "agreed" if row["label"] == row["reviewed_label"] else "corrected" for row in reviewed
        )
        return {
            "policy_name": engine.policy["name"],
            "mission": engine.policy["mission"],
            "total": total,
            "action_counts": action_counts,
            "off_mission_share": off_mission / total if total else 0.0,
            "est_cost_saved_usd": round(cost_saved, 4),
            "learned_examples": len(self.learned_examples()),
            "reviews": dict(corrections),
            "demand_clusters": engine.cluster(off_messages),
            "flagged_users": flagged,
            "review_queue": review_queue,
            "recent": recent,
        }
