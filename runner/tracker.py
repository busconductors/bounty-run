"""SQLite findings tracker — persistent memory for targets, findings, status and bounty.

Standalone module with its own CLI (``tracker.main(argv)``).  The operator wires
this into ``bounty_run.py`` as the ``track`` subcommand; this module is self-
contained and imports nothing but the stdlib.

DB location: ``~/bounty-run/tracker.db`` (override with ``get_db(path=...)`` or by
repointing ``tracker.DEFAULT_DB`` — used by the unit tests so they never touch the
real database).
"""

import argparse
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

#: Canonical finding statuses (single source of truth).
CANONICAL_STATUSES = (
    "new",
    "triaged",
    "submitted",
    "accepted",
    "paid",
    "duplicate",
    "na",
)

#: Default on-disk location.  Reassign for testability.
DEFAULT_DB = Path.home() / "bounty-run" / "tracker.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    domain TEXT UNIQUE,
    program TEXT DEFAULT '',
    scope TEXT DEFAULT '',
    created TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    target_id INTEGER,
    title TEXT,
    severity TEXT,
    url TEXT,
    template TEXT DEFAULT '',
    status TEXT DEFAULT 'new',
    bounty REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    created TEXT
);
"""


def _now() -> str:
    """ISO timestamp for `created` columns."""
    return datetime.now().isoformat(timespec="seconds")


def get_db(path=None) -> sqlite3.Connection:
    """Open (and, if missing, auto-create) the tracker DB.

    ``path`` overrides ``DEFAULT_DB``; the parent directory is created on demand.
    """
    p = Path(path) if path else DEFAULT_DB
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def _resolve_target_id(conn: sqlite3.Connection, domain: str) -> int:
    """Return the target row id for ``domain``, creating the row if absent."""
    row = conn.execute(
        "SELECT id FROM targets WHERE domain = ?", (domain,)
    ).fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        "INSERT INTO targets (domain, program, scope, created) VALUES (?, '', '', ?)",
        (domain, _now()),
    )
    conn.commit()
    assert cur.lastrowid is not None
    return cur.lastrowid


def add_target(domain, program="", scope="") -> int:
    """Register a target; returns its id.  Duplicate domains reuse the existing row."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO targets (domain, program, scope, created) "
            "VALUES (?, ?, ?, ?)",
            (domain, program, scope, _now()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id FROM targets WHERE domain = ?", (domain,)
        ).fetchone()
        return row["id"]
    finally:
        conn.close()


def add_finding(target, title, severity, url, template="", status="new",
                bounty: float = 0, notes=""):
    """Record a finding against ``target`` (domain); auto-creates the target row.

    Returns the new finding id.
    """
    conn = get_db()
    try:
        tid = _resolve_target_id(conn, target)
        cur = conn.execute(
            "INSERT INTO findings (target_id, title, severity, url, template, "
            "status, bounty, notes, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tid, title, severity, url, template, status, bounty, notes, _now()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_findings(target=None, status=None) -> list[dict]:
    """List findings, optionally filtered by target domain and/or status."""
    conn = get_db()
    try:
        sql = (
            "SELECT f.*, t.domain FROM findings f "
            "JOIN targets t ON t.id = f.target_id"
        )
        clauses, params = [], []
        if target:
            clauses.append("t.domain = ?")
            params.append(target)
        if status:
            clauses.append("f.status = ?")
            params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY f.id"
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


_UPDATEABLE = {"title", "severity", "url", "template", "status", "bounty", "notes"}


def update_finding(fid, **fields) -> bool:
    """Update a finding by id with the given column -> value fields.

    Returns True when a row was updated, False otherwise (no such id, or no
    updateable fields supplied).
    """
    updates = {k: v for k, v in fields.items() if k in _UPDATEABLE and v is not None}
    if not updates:
        return False
    conn = get_db()
    try:
        cols = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [fid]
        cur = conn.execute(f"UPDATE findings SET {cols} WHERE id = ?", vals)
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def stats() -> dict:
    """Aggregate counts by status plus total bounty and total findings."""
    conn = get_db()
    try:
        statuses = {
            row["status"]: row["n"]
            for row in conn.execute(
                "SELECT status, COUNT(*) AS n FROM findings GROUP BY status"
            )
        }
        total_bounty = conn.execute(
            "SELECT COALESCE(SUM(bounty), 0) AS b FROM findings"
        ).fetchone()["b"]
        return {
            "statuses": statuses,
            "total_findings": sum(statuses.values()),
            "total_bounty": float(total_bounty),
        }
    finally:
        conn.close()


# --- CLI ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="track",
        description="SQLite findings tracker for bounty-run.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    at = sub.add_parser("add-target", help="register a target")
    at.add_argument("domain", help="target domain (e.g. example.com)")
    at.add_argument("--program", default="", help="program name")
    at.add_argument("--scope", default="", help="in-scope notes")

    af = sub.add_parser("add-finding", help="record a finding")
    af.add_argument("target", help="target domain")
    af.add_argument("--title", required=True, help="finding title")
    af.add_argument("--severity", required=True, help="severity")
    af.add_argument("--url", default="", help="affected URL")
    af.add_argument("--template", default="", help="detector template name")
    af.add_argument("--status", default="new", choices=CANONICAL_STATUSES)
    af.add_argument("--bounty", type=float, default=0, help="bounty amount")
    af.add_argument("--notes", default="", help="free-form notes")

    ls = sub.add_parser("list", help="list findings")
    ls.add_argument("--target", help="filter by target domain")
    ls.add_argument("--status", choices=CANONICAL_STATUSES, help="filter by status")

    up = sub.add_parser("update", help="update a finding")
    up.add_argument("id", type=int, help="finding id")
    up.add_argument("--status", choices=CANONICAL_STATUSES)
    up.add_argument("--bounty", type=float)
    up.add_argument("--notes")

    sub.add_parser("stats", help="show tracker stats")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cmd = args.command

    if cmd == "add-target":
        tid = add_target(args.domain, args.program, args.scope)
        print(f"target #{tid} {args.domain}")
    elif cmd == "add-finding":
        fid = add_finding(
            args.target, args.title, args.severity, args.url,
            template=args.template, status=args.status,
            bounty=args.bounty, notes=args.notes,
        )
        print(f"finding #{fid} added for {args.target}")
    elif cmd == "list":
        rows = list_findings(target=args.target, status=args.status)
        if not rows:
            print("no findings")
        for r in rows:
            print(f"#{r['id']} [{r['status']}] {r['title']} — "
                  f"{r['domain']} (${r['bounty']:g})")
    elif cmd == "update":
        fields = {}
        if args.status is not None:
            fields["status"] = args.status
        if args.bounty is not None:
            fields["bounty"] = args.bounty
        if args.notes is not None:
            fields["notes"] = args.notes
        if update_finding(args.id, **fields):
            print(f"updated #{args.id}")
        else:
            print(f"error: no finding with id #{args.id}", file=sys.stderr)
            return 1
    elif cmd == "stats":
        s = stats()
        print(f"findings: {s['total_findings']} | bounty: ${s['total_bounty']:g}")
        for status in CANONICAL_STATUSES:
            if s["statuses"].get(status):
                print(f"  {status}: {s['statuses'][status]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
