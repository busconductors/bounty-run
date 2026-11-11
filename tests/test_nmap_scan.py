"""Tests for runner/nmap_scan.py (Phase 8)."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from runner import nmap_scan


# Two hosts: one with an sensitive (ssh) + an info (https) port, one with a
# closed port that must be ignored.
NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="198.51.100.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestCandidateIPs(unittest.TestCase):
    def test_dedupe_and_ssrf_filter(self):
        rows = [
            {"host": "a.example.com", "status": 200},
            {"host": "b.example.com", "status": 200},  # resolves to dup of target
            {"host": "down.example.com", "status": 0},  # no status -> skipped
        ]
        origins = [{"ip": "203.0.113.9"}, {"ip": "10.0.0.5"}]  # second is private

        def fake_resolve(host):
            return {"a.example.com": "93.184.216.34",
                    "b.example.com": "93.184.216.34",
                    "example.com": "93.184.216.34"}.get(host, "")

        def fake_global(ip):
            return not ip.startswith(("10.", "192.168."))

        with mock.patch.object(nmap_scan, "_resolve", side_effect=fake_resolve), \
             mock.patch.object(nmap_scan, "_is_global", side_effect=fake_global):
            ips = nmap_scan._candidate_ips("example.com", rows, origins)

        # 93.184.216.34 appears once (dedupe), private 10.0.0.5 dropped.
        self.assertEqual(ips, ["93.184.216.34", "203.0.113.9"])

    def test_cap_at_32(self):
        rows = [{"host": f"h{i}", "status": 200} for i in range(40)]
        with mock.patch.object(nmap_scan, "_resolve", side_effect=lambda h: f"8.8.{h[1:]}.1"), \
             mock.patch.object(nmap_scan, "_is_global", return_value=True):
            ips = nmap_scan._candidate_ips("example.com", rows, None)
        self.assertEqual(len(ips), 32)


class TestParsing(unittest.TestCase):
    def _findings(self):
        import xml.etree.ElementTree as ET
        findings, raw = nmap_scan._parse_hosts(ET.fromstring(NMAP_XML))
        return findings, raw

    def test_one_finding_per_open_port(self):
        findings, _ = self._findings()
        # 22, 443, 80 open; 8080 closed -> 3 findings
        self.assertEqual(len(findings), 3)

    def test_template_carries_port_and_proto(self):
        findings, _ = self._findings()
        templates = {f["template"] for f in findings}
        self.assertEqual(templates, {"nmap:22/tcp", "nmap:443/tcp", "nmap:80/tcp"})

    def test_sensitive_port_is_low(self):
        findings, _ = self._findings()
        by_tpl = {f["template"]: f for f in findings}
        self.assertEqual(by_tpl["nmap:22/tcp"]["severity"], "low")   # ssh = sensitive
        self.assertEqual(by_tpl["nmap:443/tcp"]["severity"], "info")  # https = info
        self.assertEqual(by_tpl["nmap:80/tcp"]["severity"], "info")

    def test_finding_schema_fields(self):
        findings, _ = self._findings()
        f = {x["template"]: x for x in findings}["nmap:443/tcp"]
        self.assertEqual(f["url"], "93.184.216.34")
        self.assertEqual(f["host"], "93.184.216.34")
        self.assertEqual(f["name"], "Open port 443/tcp — https")
        self.assertEqual(f["evidence"], "nginx 1.18.0")

    def test_raw_lines(self):
        _, raw = self._findings()
        self.assertIn("93.184.216.34:22/tcp ssh 8.9p1", raw)


class TestNmapScan(unittest.TestCase):
    def test_happy_path_writes_artifacts(self):
        rows = [{"host": "example.com", "status": 200}]
        with TemporaryDirectory() as d:
            outdir = Path(d)

            def fake_run(cmd, timeout=900):
                (outdir / "nmap.xml").write_text(NMAP_XML)
                return ""

            with mock.patch.object(nmap_scan.utils, "have", return_value=True), \
                 mock.patch.object(nmap_scan, "_resolve", return_value="93.184.216.34"), \
                 mock.patch.object(nmap_scan, "_is_global", return_value=True), \
                 mock.patch.object(nmap_scan.utils, "log"), \
                 mock.patch.object(nmap_scan.utils, "warn"), \
                 mock.patch.object(nmap_scan.utils, "run", side_effect=fake_run):
                findings = nmap_scan.nmap_scan("example.com", outdir, rows)

            self.assertEqual(len(findings), 3)
            self.assertTrue((outdir / "nmap_open_ports.txt").exists())

    def test_default_uses_top_ports(self):
        rows = [{"host": "example.com", "status": 200}]
        captured = {}
        with TemporaryDirectory() as d:
            outdir = Path(d)

            def fake_run(cmd, timeout=900):
                captured["cmd"] = cmd
                (outdir / "nmap.xml").write_text(NMAP_XML)
                return ""

            with mock.patch.object(nmap_scan.utils, "have", return_value=True), \
                 mock.patch.object(nmap_scan, "_resolve", return_value="93.184.216.34"), \
                 mock.patch.object(nmap_scan, "_is_global", return_value=True), \
                 mock.patch.object(nmap_scan.utils, "log"), \
                 mock.patch.object(nmap_scan.utils, "warn"), \
                 mock.patch.object(nmap_scan.utils, "run", side_effect=fake_run):
                nmap_scan.nmap_scan("example.com", outdir, rows)

        self.assertIn("--top-ports 1000", captured["cmd"])
        self.assertIn("--open", captured["cmd"])
        self.assertNotIn("-p-", captured["cmd"])

    def test_full_uses_all_ports(self):
        rows = [{"host": "example.com", "status": 200}]
        captured = {"cmds": []}
        with TemporaryDirectory() as d:
            outdir = Path(d)

            def fake_run(cmd, timeout=900):
                captured["cmds"].append(cmd)
                (outdir / "nmap.xml").write_text(NMAP_XML)
                return ""

            with mock.patch.object(nmap_scan.utils, "have", return_value=True), \
                 mock.patch.object(nmap_scan, "_resolve", return_value="93.184.216.34"), \
                 mock.patch.object(nmap_scan, "_is_global", return_value=True), \
                 mock.patch.object(nmap_scan.utils, "log"), \
                 mock.patch.object(nmap_scan.utils, "warn"), \
                 mock.patch.object(nmap_scan.utils, "run", side_effect=fake_run):
                nmap_scan.nmap_scan("example.com", outdir, rows, full=True)

        # Two phases: SYN discovery over all ports, then service scan on open ports.
        self.assertEqual(len(captured["cmds"]), 2)
        discovery, services = captured["cmds"]
        self.assertIn("-p-", discovery)
        self.assertIn("--open", discovery)
        self.assertNotIn("-sV", discovery)
        self.assertIn("--max-retries 2", discovery)
        self.assertIn("-sV", services)
        self.assertIn("-p 22,80,443", services)

    def test_full_zero_open_ports_returns_empty(self):
        rows = [{"host": "example.com", "status": 200}]
        empty_xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
        captured = {"cmds": []}
        with TemporaryDirectory() as d:
            outdir = Path(d)

            def fake_run(cmd, timeout=900):
                captured["cmds"].append(cmd)
                (outdir / "nmap.xml").write_text(empty_xml)
                return ""

            with mock.patch.object(nmap_scan.utils, "have", return_value=True), \
                 mock.patch.object(nmap_scan, "_resolve", return_value="93.184.216.34"), \
                 mock.patch.object(nmap_scan, "_is_global", return_value=True), \
                 mock.patch.object(nmap_scan.utils, "log"), \
                 mock.patch.object(nmap_scan.utils, "warn"), \
                 mock.patch.object(nmap_scan.utils, "run", side_effect=fake_run):
                findings = nmap_scan.nmap_scan("example.com", outdir, rows, full=True)

            # Only phase 1 runs; nothing open, so no phase 2 service scan.
            self.assertEqual(len(captured["cmds"]), 1)
            self.assertEqual(findings, [])
            self.assertTrue((outdir / "nmap_open_ports.txt").exists())

    def test_missing_nmap_returns_empty(self):
        with mock.patch.object(nmap_scan.utils, "have", return_value=False), \
             mock.patch.object(nmap_scan.utils, "warn"), \
             mock.patch.object(nmap_scan.utils, "log"):
            self.assertEqual(nmap_scan.nmap_scan("example.com", Path("/tmp"), []), [])

    def test_no_ips_returns_empty(self):
        with mock.patch.object(nmap_scan.utils, "have", return_value=True), \
             mock.patch.object(nmap_scan, "_resolve", return_value=""), \
             mock.patch.object(nmap_scan.utils, "warn"), \
             mock.patch.object(nmap_scan.utils, "log"), \
             mock.patch.object(nmap_scan.utils, "run") as run:
            result = nmap_scan.nmap_scan("example.com", Path("/tmp"), None, None)
        self.assertEqual(result, [])
        run.assert_not_called()

    def test_bad_xml_returns_empty(self):
        rows = [{"host": "example.com", "status": 200}]
        with TemporaryDirectory() as d:
            outdir = Path(d)

            def fake_run(cmd, timeout=900):
                (outdir / "nmap.xml").write_text("<nmaprun><host>broken")
                return ""

            with mock.patch.object(nmap_scan.utils, "have", return_value=True), \
                 mock.patch.object(nmap_scan, "_resolve", return_value="93.184.216.34"), \
                 mock.patch.object(nmap_scan, "_is_global", return_value=True), \
                 mock.patch.object(nmap_scan.utils, "log"), \
                 mock.patch.object(nmap_scan.utils, "warn"), \
                 mock.patch.object(nmap_scan.utils, "run", side_effect=fake_run):
                findings = nmap_scan.nmap_scan("example.com", outdir, rows)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
