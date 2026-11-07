"""Unit tests for runner.tracker (SQLite findings tracker).

Stdlib unittest only.  Every test repoints ``tracker.DEFAULT_DB`` at a throwaway
temp file so the real ``~/bounty-run/tracker.db`` is never touched:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_tracker.py -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import tracker  # noqa: E402


class TrackerTestCase(unittest.TestCase):
    """Base: redirect the tracker to a fresh temp DB for each test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_db = tracker.DEFAULT_DB
        tracker.DEFAULT_DB = Path(self._tmp.name) / "tracker.db"
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(setattr, tracker, "DEFAULT_DB", self._orig_db)

    def _target_ids(self):
        conn = tracker.get_db()
        try:
            return [r["domain"] for r in conn.execute("SELECT domain FROM targets")]
        finally:
            conn.close()


class TestAddTargetAndRoundTrip(TrackerTestCase):
    def test_add_target_returns_id_and_roundtrips(self):
        tid = tracker.add_target("example.com", program="Acme", scope="*.example.com")
        self.assertIsInstance(tid, int)
        conn = tracker.get_db()
        try:
            row = conn.execute(
                "SELECT domain, program, scope FROM targets WHERE id = ?", (tid,)
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["domain"], "example.com")
        self.assertEqual(row["program"], "Acme")
        self.assertEqual(row["scope"], "*.example.com")

    def test_duplicate_domain_does_not_create_second_row(self):
        first = tracker.add_target("example.com")
        second = tracker.add_target("example.com")
        self.assertEqual(first, second)
        self.assertEqual(len(self._target_ids()), 1)

    def test_duplicate_domain_reuses_existing_row(self):
        tracker.add_target("example.com", program="Acme")
        again = tracker.add_target("example.com", program="Other")
        conn = tracker.get_db()
        try:
            rows = conn.execute(
                "SELECT id, program FROM targets WHERE domain = 'example.com'"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], again)


class TestAddFinding(TrackerTestCase):
    def test_add_finding_roundtrips_via_list(self):
        tid = tracker.add_target("example.com")
        fid = tracker.add_finding(
            "example.com", "SQLi in search", "high",
            "https://example.com/search?q=x", template="sqli", bounty=1500.0,
        )
        rows = tracker.list_findings()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["id"], fid)
        self.assertEqual(r["target_id"], tid)
        self.assertEqual(r["domain"], "example.com")
        self.assertEqual(r["title"], "SQLi in search")
        self.assertEqual(r["severity"], "high")
        self.assertEqual(r["url"], "https://example.com/search?q=x")
        self.assertEqual(r["template"], "sqli")
        self.assertEqual(r["status"], "new")
        self.assertEqual(r["bounty"], 1500.0)
        self.assertEqual(r["notes"], "")
        self.assertIsNotNone(r["created"])

    def test_add_finding_auto_creates_target_row(self):
        fid = tracker.add_finding("unknown.com", "XSS", "medium", "https://unknown.com/a")
        self.assertIn("unknown.com", self._target_ids())
        rows = tracker.list_findings(target="unknown.com")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], fid)


class TestUpdateFinding(TrackerTestCase):
    def test_update_changes_status_and_bounty(self):
        fid = tracker.add_finding("example.com", "XSS", "medium", "https://x/")
        tracker.update_finding(fid, status="paid", bounty=500.0, notes="payout #12")
        rows = tracker.list_findings()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "paid")
        self.assertEqual(rows[0]["bounty"], 500.0)
        self.assertEqual(rows[0]["notes"], "payout #12")

    def test_update_ignores_unknown_fields(self):
        fid = tracker.add_finding("example.com", "XSS", "medium", "https://x/")
        tracker.update_finding(fid, status="triaged", bogus="drop; table")
        rows = tracker.list_findings()
        self.assertEqual(rows[0]["status"], "triaged")
        self.assertEqual(rows[0]["title"], "XSS")


class TestStats(TrackerTestCase):
    def test_stats_counts_statuses_and_totals_bounty(self):
        tracker.add_finding("a.com", "f1", "high", "https://a/1", status="new", bounty=100.0)
        tracker.add_finding("a.com", "f2", "high", "https://a/2", status="triaged", bounty=200.0)
        tracker.add_finding("b.com", "f3", "low", "https://b/1", status="paid", bounty=700.0)
        tracker.add_finding("b.com", "f4", "low", "https://b/2", status="paid", bounty=0.0)

        s = tracker.stats()
        self.assertEqual(s["total_findings"], 4)
        self.assertEqual(s["total_bounty"], 1000.0)
        self.assertEqual(s["statuses"], {"new": 1, "triaged": 1, "paid": 2})

    def test_stats_empty_db(self):
        s = tracker.stats()
        self.assertEqual(s["total_findings"], 0)
        self.assertEqual(s["total_bounty"], 0.0)
        self.assertEqual(s["statuses"], {})


class TestListFilters(TrackerTestCase):
    def test_filter_by_target_and_status(self):
        tracker.add_finding("a.com", "f1", "high", "https://a/1", status="new")
        tracker.add_finding("a.com", "f2", "high", "https://a/2", status="paid")
        tracker.add_finding("b.com", "f3", "high", "https://b/1", status="new")

        self.assertEqual(len(tracker.list_findings()), 3)
        self.assertEqual(len(tracker.list_findings(target="a.com")), 2)
        self.assertEqual(len(tracker.list_findings(status="new")), 2)
        self.assertEqual(len(tracker.list_findings(target="b.com", status="new")), 1)
        self.assertEqual(len(tracker.list_findings(target="b.com", status="paid")), 0)


class TestCli(TrackerTestCase):
    def test_cli_add_target_and_stats(self):
        self.assertEqual(tracker.main(["add-target", "example.com", "--program", "Acme"]), 0)
        self.assertEqual(tracker.main(["add-finding", "example.com", "--title", "XSS",
                                       "--severity", "high", "--bounty", "250"]), 0)
        rows = tracker.list_findings()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["bounty"], 250.0)

    def test_cli_update(self):
        fid = tracker.add_finding("example.com", "XSS", "medium", "https://x/")
        self.assertEqual(tracker.main(["update", str(fid), "--status", "paid",
                                       "--bounty", "99"]), 0)
        self.assertEqual(tracker.list_findings()[0]["status"], "paid")


if __name__ == "__main__":
    unittest.main(verbosity=2)
