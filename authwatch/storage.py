"""SQLite-backed history.

authwatch can run as a one-shot tool, but it's much more useful when you
run it on a cron / schedule and it remembers what it has already flagged.

The DB has two tables:

    events     — every AuthEvent we ingested (deduped by (ts, ip, user, source))
    findings   — one row per detection run

We keep the schema tiny on purpose. If you need heavy querying, export to
CSV and open it in something made for that job.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from .detectors import Finding
from .events import AuthEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    ts       TEXT NOT NULL,
    ip       TEXT NOT NULL,
    user     TEXT,
    success  INTEGER NOT NULL,
    source   TEXT NOT NULL,
    PRIMARY KEY (ts, ip, user, source)
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    ip             TEXT,
    user           TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    fails          INTEGER NOT NULL,
    successes      INTEGER NOT NULL,
    distinct_users INTEGER NOT NULL DEFAULT 0,
    distinct_ips   INTEGER NOT NULL DEFAULT 0,
    sources        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_ip ON findings(ip);
CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user);
"""


@contextmanager
def connect(path: str | Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_SCHEMA)
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_events(conn: sqlite3.Connection, events: Iterable[AuthEvent]) -> int:
    """Insert events, ignoring exact duplicates. Returns count of new rows."""
    cur = conn.executemany(
        "INSERT OR IGNORE INTO events (ts, ip, user, success, source) "
        "VALUES (?, ?, ?, ?, ?)",
        [
            (
                e.ts.isoformat(timespec="seconds"),
                e.ip,
                e.user,
                1 if e.success else 0,
                e.source,
            )
            for e in events
        ],
    )
    return cur.rowcount or 0


def save_findings(
    conn: sqlite3.Connection, findings: Iterable[Finding], created_at: str
) -> int:
    data = [
        (
            created_at,
            f.kind,
            f.ip,
            f.user,
            f.first_seen,
            f.last_seen,
            f.fails,
            f.successes,
            f.distinct_users,
            f.distinct_ips,
            ",".join(f.sources),
        )
        for f in findings
    ]
    if not data:
        return 0
    cur = conn.executemany(
        "INSERT INTO findings "
        "(created_at, kind, ip, user, first_seen, last_seen, fails, successes, "
        " distinct_users, distinct_ips, sources) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        data,
    )
    return cur.rowcount or 0


def repeat_offenders(conn: sqlite3.Connection, min_occurrences: int = 2) -> list[tuple[str, int]]:
    """Return IPs that appeared in findings across >= min_occurrences distinct runs."""
    rows = conn.execute(
        "SELECT ip, COUNT(DISTINCT created_at) AS runs "
        "FROM findings WHERE ip IS NOT NULL "
        "GROUP BY ip HAVING runs >= ? ORDER BY runs DESC",
        (min_occurrences,),
    ).fetchall()
    return [(ip, runs) for ip, runs in rows]
