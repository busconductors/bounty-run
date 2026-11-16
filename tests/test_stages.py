"""Unit tests for runner.stages security fixes.

Hermetic — no network, no external tools. Run with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_stages.py -v
"""
import ipaddress
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import stages  # noqa: E402
from runner import utils  # noqa: E402


class FakeResp:
    def __init__(self, headers, status_code=200, url="https://example.com"):
        self.headers = headers
        self.status_code = status_code
        self.url = url
        self.closed = False

    def close(self):
        self.closed = True


class IsGlobalTests(unittest.TestCase):
    def test_public_ip_is_global(self):
        self.assertTrue(stages._is_global("8.8.8.8"))
        self.assertTrue(stages._is_global("1.1.1.1"))

    def test_loopback_and_private_are_not_global(self):
        self.assertFalse(stages._is_global("127.0.0.1"))
        self.assertFalse(stages._is_global("10.0.0.1"))
        self.assertFalse(stages._is_global("192.168.1.1"))
        self.assertFalse(stages._is_global("172.16.0.1"))

    def test_link_local_metadata_is_not_global(self):
        self.assertFalse(stages._is_global("169.254.169.254"))

    def test_invalid_ip_returns_false(self):
        self.assertFalse(stages._is_global("not-an-ip"))
        self.assertFalse(stages._is_global(""))
        self.assertFalse(stages._is_global("999.999.999.999"))


class ProbeHostTests(unittest.TestCase):
    def test_non_global_ip_is_never_probed(self):
        with mock.patch.object(stages.socket, "gethostbyname", return_value="127.0.0.1"), \
             mock.patch.object(stages, "requests") as req:
            row = stages._probe_host("evil.internal", 5)
        self.assertEqual(row, {"host": "evil.internal", "url": "", "status": 0,
                               "server": "", "cloudflare": False})
        req.get.assert_not_called()

    def test_dns_failure_returns_safe_row(self):
        with mock.patch.object(stages.socket, "gethostbyname",
                               side_effect=Exception("nope")), \
             mock.patch.object(stages, "requests") as req:
            row = stages._probe_host("does-not-resolve", 5)
        self.assertEqual(row["status"], 0)
        req.get.assert_not_called()

    def test_global_ip_probes_with_no_redirects_and_streams(self):
        resp = FakeResp({"Server": "cloudflare", "cf-ray": "abc"})
        with mock.patch.object(stages.socket, "gethostbyname", return_value="8.8.8.8"), \
             mock.patch.object(stages, "requests") as req:
            req.get.return_value = resp
            row = stages._probe_host("example.com", 5)
        _, kwargs = req.get.call_args
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])
        self.assertTrue(resp.closed)
        self.assertEqual(row["status"], 200)
        self.assertTrue(row["cloudflare"])


class VerifyOriginTests(unittest.TestCase):
    def test_curl_includes_insecure_flag(self):
        with mock.patch.object(utils, "run") as run:
            run.return_value = "200|1.2.3.4"
            stages._verify_origin("example.com", "1.2.3.4")
        cmd = run.call_args[0][0]
        self.assertIn("-k", cmd)
        self.assertIn("--resolve example.com:443:1.2.3.4", cmd)


class OriginHuntFilterTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        # Hermetic: no CNAMEs unless a test says otherwise (name is its own canonical).
        p = mock.patch.object(stages, "_canonical_name", side_effect=lambda h: h)
        self.canonical = p.start()
        self.addCleanup(p.stop)

    def _hunt(self, resolve_map, mx=()):
        """Run origin_hunt with a fake resolver/MX set; return (rows, verify mock)."""
        cf_ranges = [ipaddress.ip_network("104.16.0.0/13")]
        with mock.patch.object(stages, "_resolve", side_effect=lambda h: resolve_map.get(h, "")) as res, \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=cf_ranges), \
             mock.patch.object(stages, "_mx_hosts", return_value=list(mx)), \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_verify_origin",
                               side_effect=lambda t, ip: {"status": "200", "remote_ip": ip}) as verify:
            rows = stages.origin_hunt("yoco.com", self.outdir, {"ip": "104.16.1.1"})
        self.resolved = [c.args[0] for c in res.call_args_list]
        return rows, verify

    def test_google_workspace_mx_is_not_an_origin_candidate(self):
        # yoco.com regression: MX -> Google Workspace must never become an origin.
        google = {"aspmx.l.google.com": "142.250.27.27",
                  "alt1.aspmx.l.google.com": "142.251.9.27",
                  "alt2.aspmx.l.google.com": "192.178.164.27"}
        rows, verify = self._hunt(google, mx=list(google))
        self.assertEqual(rows, [])
        verify.assert_not_called()
        for mx in google:  # not even resolved
            self.assertNotIn(mx, self.resolved)
        self.assertNotIn("142.250.27.27",
                         (self.outdir / "origin_candidates.txt").read_text())

    def test_third_party_mx_providers_are_not_origin_candidates(self):
        # netcare.co.za regression (Mimecast) + Microsoft 365 / Proofpoint.
        mx = ["za-smtp-inbound-2.mimecast.co.za", "yoco-com.mail.protection.outlook.com",
              "mxa-001.pphosted.com"]
        rows, _ = self._hunt({h: "41.74.193.10" for h in mx}, mx=mx)
        self.assertEqual(rows, [])

    def test_lookalike_domain_mx_is_not_in_domain(self):
        # "notyoco.com" ends with "yoco.com" as a string but is not a subdomain.
        rows, _ = self._hunt({"mx.notyoco.com": "5.6.7.8"}, mx=["mx.notyoco.com"])
        self.assertEqual(rows, [])

    def test_self_hosted_mx_in_target_domain_is_still_a_candidate(self):
        rows, _ = self._hunt({"mx.yoco.com": "5.6.7.8"}, mx=["mx.yoco.com"])
        self.assertEqual([(r["ip"], r["sources"]) for r in rows],
                         [("5.6.7.8", ["mx.yoco.com", "MX:mx.yoco.com"])])

    def test_leak_subdomain_cnamed_to_provider_is_not_a_candidate(self):
        # autodiscover -> Microsoft, mail -> Google Sites: in-zone names, provider IPs.
        cnames = {"autodiscover.yoco.com": "autodiscover.outlook.com",
                  "mail.yoco.com": "ghs.googlehosted.com"}
        self.canonical.side_effect = lambda h: cnames.get(h, h)
        rows, verify = self._hunt({"autodiscover.yoco.com": "52.97.1.1",
                                   "mail.yoco.com": "142.250.1.1",
                                   "direct.yoco.com": "5.6.7.8"})
        self.assertEqual([r["ip"] for r in rows], ["5.6.7.8"])
        self.assertEqual(verify.call_count, 1)

    def test_leak_subdomain_cnamed_within_target_is_kept(self):
        self.canonical.side_effect = lambda h: "origin.yoco.com" if h == "direct.yoco.com" else h
        rows, _ = self._hunt({"direct.yoco.com": "5.6.7.8"})
        self.assertEqual([r["ip"] for r in rows], ["5.6.7.8"])

    def test_unknown_canonical_name_fails_closed(self):
        self.canonical.side_effect = lambda h: ""
        rows, _ = self._hunt({"direct.yoco.com": "5.6.7.8"})
        self.assertEqual(rows, [])

    def test_private_and_loopback_ips_are_not_recorded(self):
        cf_ranges = [ipaddress.ip_network("1.2.3.0/24")]
        with mock.patch.object(stages, "_resolve", return_value="127.0.0.1"), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(cf_ranges)), \
             mock.patch.object(stages, "_mx_hosts", return_value=[]), \
             mock.patch.object(stages, "_verify_origin") as verify:
            rows = stages.origin_hunt("example.com", self.outdir, {})
        self.assertEqual(rows, [])
        verify.assert_not_called()

    def test_public_origin_is_recorded(self):
        cf_ranges = [ipaddress.ip_network("1.2.3.0/24")]
        with mock.patch.object(stages, "_resolve", return_value="5.6.7.8"), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(cf_ranges)), \
             mock.patch.object(stages, "_mx_hosts", return_value=[]), \
             mock.patch.object(stages, "_verify_origin",
                               return_value={"status": "200", "remote_ip": "5.6.7.8"}):
            rows = stages.origin_hunt("example.com", self.outdir, {})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "5.6.7.8")


class OwnershipHelperTests(unittest.TestCase):
    def test_in_domain(self):
        self.assertTrue(stages._in_domain("yoco.com", "yoco.com"))
        self.assertTrue(stages._in_domain("MX.Yoco.com.", "yoco.com"))
        self.assertFalse(stages._in_domain("aspmx.l.google.com", "yoco.com"))
        self.assertFalse(stages._in_domain("notyoco.com", "yoco.com"))
        self.assertFalse(stages._in_domain("", "yoco.com"))

    def test_canonical_name_follows_cname_and_fails_empty(self):
        with mock.patch.object(stages.socket, "gethostbyname_ex",
                               return_value=("ghs.googlehosted.com.", ["mail.yoco.com"], ["1.2.3.4"])):
            self.assertEqual(stages._canonical_name("mail.yoco.com"), "ghs.googlehosted.com")
        with mock.patch.object(stages.socket, "gethostbyname_ex", side_effect=OSError("nx")):
            self.assertEqual(stages._canonical_name("x.yoco.com"), "")


class VulnScanTests(unittest.TestCase):
    def setUp(self):
        # A scratch dir whose path contains a space to exercise shell quoting.
        self._tmp = tempfile.mkdtemp(prefix="bounty run ")
        self.outdir = Path(self._tmp)
        self.addCleanup(lambda: __import__("shutil").rmtree(self._tmp))

    def _run_scan(self, live_rows):
        with mock.patch.object(utils, "have", return_value=True), \
             mock.patch.object(utils, "run", return_value="") as run, \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_resolve",
                               side_effect=lambda h: {"example.com": "8.8.8.8",
                                                      "internal.example.com": "10.0.0.1"}.get(h, "")):
            stages.vuln_scan("example.com", self.outdir, live_rows)
        return run

    def test_paths_are_shell_quoted(self):
        run = self._run_scan([{"host": "example.com", "status": 200}])
        cmd = run.call_args[0][0]
        self.assertIn(shlex.quote(str(self.outdir / "nuclei.jsonl")), cmd)
        self.assertIn(shlex.quote(str(self.outdir / "nuclei_targets.txt")), cmd)

    def test_origin_ips_are_not_appended_as_bare_urls(self):
        # Origin IPs must NOT be added to the hostname target list — a bare IP
        # makes nuclei send SNI/Host=<ip>, which the origin cannot route.
        self._run_scan_with_origins(
            [{"host": "example.com", "status": 200}],
            origins=[{"ip": "5.6.7.8"}, {"ip": "9.10.11.12"}],
        )
        targets = (self.outdir / "nuclei_targets.txt").read_text().splitlines()
        self.assertIn("example.com", targets)
        for bare in ("https://5.6.7.8", "http://5.6.7.8",
                     "https://9.10.11.12", "http://9.10.11.12"):
            self.assertNotIn(bare, targets)

    def test_origin_pass_uses_sni_and_host_header(self):
        # Each origin IP gets its own nuclei pass that forces SNI + Host so it
        # reaches the real origin behind Cloudflare with the right vhost.
        run = self._run_scan_with_origins(
            [{"host": "example.com", "status": 200}],
            origins=[{"ip": "5.6.7.8"}, {"ip": "9.10.11.12"}],
        )
        origin_cmds = [c.args[0] for c in run.call_args_list
                       if "nuclei_origin_" in c.args[0]]
        self.assertEqual(len(origin_cmds), 2)
        for ip, cmd in zip(("5.6.7.8", "9.10.11.12"), origin_cmds):
            self.assertIn("-sni example.com", cmd)
            self.assertIn(shlex.quote("Host: example.com"), cmd)
            # Reaches the origin IP, not the hostname (which resolves to edge).
            targets = (self.outdir / f"nuclei_origin_{ip}.txt").read_text().splitlines()
            self.assertIn(f"https://{ip}", targets)
            self.assertIn(f"http://{ip}", targets)

    def test_origin_ips_are_deduped(self):
        run = self._run_scan_with_origins(
            [{"host": "example.com", "status": 200}],
            origins=[{"ip": "5.6.7.8"}, {"ip": "5.6.7.8"}, {"ip": None}, {}],
        )
        origin_cmds = [c.args[0] for c in run.call_args_list
                       if "nuclei_origin_" in c.args[0]]
        # One pass for the single unique IP; None/empty origins are skipped.
        self.assertEqual(len(origin_cmds), 1)
        self.assertIn("nuclei_origin_5.6.7.8", origin_cmds[0])

    def _run_scan_with_origins(self, live_rows, origins):
        with mock.patch.object(utils, "have", return_value=True), \
             mock.patch.object(utils, "run", return_value="") as run, \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_resolve",
                               side_effect=lambda h: {"example.com": "8.8.8.8"}.get(h, "")):
            stages.vuln_scan("example.com", self.outdir, live_rows, origins=origins)
        return run

    def test_non_global_hosts_are_excluded(self):
        self._run_scan([
            {"host": "example.com", "status": 200},
            {"host": "internal.example.com", "status": 200},
        ])
        targets = (self.outdir / "nuclei_targets.txt").read_text().splitlines()
        self.assertEqual(targets, ["example.com"])

    def test_info_field_crash_shapes_do_not_raise(self):
        jl = self.outdir / "nuclei.jsonl"
        jl.write_text("\n".join([
            '{"info": "a string", "template-id": "t1", "matched-at": "https://x", "host": "example.com"}',
            '{"info": {"severity": null, "name": "n2"}, "template-id": "t2"}',
            '{"info": {"severity": ["high"], "name": "n3"}, "template-id": "t3"}',
            '{"info": {"severity": "HIGH", "name": "n4"}, "template-id": "t4"}',
            '{"info": {}}',
            'not-json',
            '["list", "not", "dict"]',
        ]))
        with mock.patch.object(utils, "have", return_value=True), \
             mock.patch.object(utils, "run", return_value=""), \
             mock.patch.object(utils, "log"), \
             mock.patch.object(stages, "_resolve", return_value="8.8.8.8"):
            findings = stages.vuln_scan("example.com", self.outdir,
                                        [{"host": "example.com", "status": 200}])

        sevs = sorted(f["severity"] for f in findings)
        self.assertEqual(sevs, ["['high']", "high", "unknown", "unknown", "unknown"])
        names = sorted(f["name"] for f in findings if f["name"])
        self.assertEqual(names, ["n2", "n3", "n4"])

    def test_jsonl_with_line_separator_parses(self):
        # A nuclei finding whose embedded response body contains a Unicode line
        # separator (U+2028) must still parse: str.splitlines() shatters the
        # single JSONL line into fragments and silently drops the finding.
        jl = self.outdir / "nuclei.jsonl"
        jl.write_text(
            '{"info": {"severity": "medium", "name": "Line-sep finding"}, '
            '"template-id": "CVE-2021-24891", "matched-at": "https://x/a.js", '
            '"host": "example.com", "response": "body\u2028with\u2029seps"}'
        )
        findings = stages._parse_nuclei_jsonl(jl)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(findings[0]["host"], "example.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
