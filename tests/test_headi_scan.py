"""Tests for runner/headi_scan.py (Phase 7b, Feature 3)."""
import unittest
from pathlib import Path
from unittest import mock

from runner import headi_scan


HEADI_OUT = (
    "[+] [https://example.com/] [Host: 127.0.0.1] [Code: 200] [Size: 1532]\n"
    "[-] [https://example.com/] [X-Forwarded-For: 127.0.0.1] [Code: 200] [Size: 992]\n"
    "[+] [https://example.com/] [X-Real-IP: 127.0.0.1] [Code: 200] [Size: 992]\n"
)


class TestParseLine(unittest.TestCase):
    def test_plus_becomes_finding_high_for_host(self):
        line = "[+] [https://example.com/] [Host: 127.0.0.1] [Code: 200] [Size: 1532]"
        findings = headi_scan._parse_line(line, "https://example.com/", "example.com")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["template"], "headi:host")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["host"], "example.com")

    def test_minus_ignored(self):
        line = "[-] [https://example.com/] [X-Forwarded-For: 127.0.0.1] [Code: 200] [Size: 992]"
        self.assertEqual(headi_scan._parse_line(line, "https://example.com/", "example.com"), [])

    def test_non_host_header_medium(self):
        line = "[+] [https://example.com/] [X-Real-IP: 127.0.0.1] [Code: 200] [Size: 992]"
        findings = headi_scan._parse_line(line, "https://example.com/", "example.com")
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(findings[0]["template"], "headi:x-real-ip")

    def test_garbage_line_ignored(self):
        self.assertEqual(headi_scan._parse_line("garbage", "u", "h"), [])


class TestHeadIScan(unittest.TestCase):
    def test_scan_happy_path(self):
        rows = [{"host": "example.com", "status": 200}]
        with mock.patch.object(headi_scan, "_resolve_binary", return_value="/usr/bin/headi"), \
             mock.patch.object(headi_scan, "_is_global", return_value=True), \
             mock.patch.object(headi_scan, "_resolve", return_value="93.184.216.34"), \
             mock.patch.object(headi_scan.utils, "log"), \
             mock.patch.object(headi_scan.utils, "warn"), \
             mock.patch.object(headi_scan.utils, "run", return_value=HEADI_OUT):
            findings = headi_scan.headi_scan("example.com", Path("/tmp"), rows)
        # two '+' lines -> two findings
        self.assertEqual(len(findings), 2)

    def test_missing_binary_returns_empty(self):
        with mock.patch.object(headi_scan, "_resolve_binary", return_value=None), \
             mock.patch.object(headi_scan.utils, "warn"):
            self.assertEqual(headi_scan.headi_scan("example.com", Path("/tmp"), []), [])

    def test_ssrf_skip_private(self):
        rows = [{"host": "localhost", "status": 200}]
        with mock.patch.object(headi_scan, "_resolve_binary", return_value="/usr/bin/headi"), \
             mock.patch.object(headi_scan, "_resolve", return_value="127.0.0.1"), \
             mock.patch.object(headi_scan.utils, "log"), \
             mock.patch.object(headi_scan.utils, "warn"):
            findings = headi_scan.headi_scan("example.com", Path("/tmp"), rows)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
