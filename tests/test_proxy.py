"""Run-level proxy (--proxy): parsing, per-tool matrix, redaction, fail-closed
gating, CLI propagation, and a live loopback SOCKS5 round-trip."""
import http.server
import json
import os
import select
import shutil
import socket
import socketserver
import struct
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

from runner import (api_endpoints, cli, events, headi_scan, http_headers, metis_check,
                    nikto_scan, origin_deep, param_scan, proxy, stages, tech_scan,
                    tls_scan, utils, waf_scan)

VENDOR = Path(__file__).resolve().parents[1] / "runner" / "vendor"


# --------------------------------------------------------------------------- #
# parse
# --------------------------------------------------------------------------- #
ACCEPT = [
    ("http://127.0.0.1:8080", "http", "127.0.0.1", 8080, None, None, "http"),
    ("https://proxy.example.com:443", "https", "proxy.example.com", 443, None, None, "https"),
    ("socks5://10.8.0.1:1080", "socks5", "10.8.0.1", 1080, None, None, "socks5"),
    ("socks5h://user:p%40ss@10.8.0.1:1080", "socks5h", "10.8.0.1", 1080, "user", "p@ss", "socks5"),
    ("HTTP://LocalHost:3128/", "http", "localhost", 3128, None, None, "http"),
    ("http://[::1]:8080", "http", "::1", 8080, None, None, "http"),
    ("  http://h:1  ", "http", "h", 1, None, None, "http"),
    ("http://u%3Ax:pw@h:65535", "http", "h", 65535, "u:x", "pw", "http"),
    ("http://u@h:80", "http", "h", 80, "u", None, "http"),
]

REJECT = [
    ("127.0.0.1:8080", "scheme"),
    ("socks4://h:1080", "unsupported proxy scheme"),
    ("socks4a://h:1080", "unsupported proxy scheme"),
    ("ftp://h:21", "unsupported proxy scheme"),
    ("http://h", "port"),
    ("http://h:0", "port"),
    ("http://h:65536", "port"),
    ("http://h:80a", "port"),
    ("http://h:1;id", "port"),
    ("http://h:8080/path", "path"),
    ("http://h:8080?x=1", "query"),
    ("http://h:8080#f", "fragment"),
    ("http://h :8080", "whitespace"),
    ("http://:8080", "host"),
    ("http://bad_host:8080", "host"),
    ("http://999.1.1.1:8080", "host"),
    ("http://[::1:8080", "IPv6"),
    ("http://[1.2.3.4]:8080", "IPv6"),
    ("http://a@b@h:8080", "credentials"),
    ("http://:pw@h:8080", "username"),
    ("http://us er:pw@h:8080", "whitespace"),
    ("", "empty"),
]


@pytest.mark.parametrize("raw,scheme,host,port,user,pw,kind", ACCEPT)
def test_parse_accepts(raw, scheme, host, port, user, pw, kind):
    c = proxy.parse(raw)
    assert (c.scheme, c.host, c.port, c.username, c.password, c.kind) == \
        (scheme, host, port, user, pw, kind)


@pytest.mark.parametrize("raw,why", REJECT)
def test_parse_rejects(raw, why):
    with pytest.raises(ValueError) as e:
        proxy.parse(raw)
    assert why.lower() in str(e.value).lower()


def test_missing_scheme_message():
    with pytest.raises(ValueError, match=r"proxy needs a scheme: http://, https://, socks5:// or socks5h://"):
        proxy.parse("127.0.0.1:8080")


def test_url_roundtrip_and_ipv6():
    assert proxy.parse("socks5h://user:p%40ss@10.8.0.1:1080").url == \
        "socks5h://user:p%40ss@10.8.0.1:1080"
    assert proxy.parse("http://[::1]:8080").url == "http://[::1]:8080"


# --------------------------------------------------------------------------- #
# redaction / secrets / env
# --------------------------------------------------------------------------- #
def test_redacted_never_contains_password():
    c = proxy.parse("socks5h://user:p%40ss@10.8.0.1:1080")
    assert c.redacted == "socks5h://user:***@10.8.0.1:1080"
    assert "p@ss" not in c.redacted and "p%40ss" not in c.redacted
    assert proxy.parse("http://h:1").redacted == "http://h:1"


def test_secrets_cover_all_forms_and_regex_metachars():
    c = proxy.parse("http://bob:a.%2A%5B%28x@h:8080")   # password "a.*[(x"
    assert c.password == "a.*[(x"
    text = f"proxy {c.url} pw={c.password} enc=a.%2A%5B%28x cred={c.userpass}"
    red = proxy.redact(text, c)
    assert "a.*[(x" not in red and "a.%2A%5B%28x" not in red
    assert red.count("***") >= 3


def test_env_sets_all_vars_and_clears_no_proxy():
    c = proxy.parse("socks5://h:1080")
    env = c.env()
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        assert env[k] == "socks5://h:1080"
    assert env["NO_PROXY"] == "" and env["no_proxy"] == ""


def test_from_env():
    assert proxy.from_env({}) is None
    assert proxy.from_env({"BOUNTY_RUN_PROXY": "http://h:1"}).port == 1
    with pytest.raises(ValueError):
        proxy.from_env({"BOUNTY_RUN_PROXY": "h:1"})


def test_ambient_env():
    assert proxy.ambient_env({"HTTPS_PROXY": "http://x:1", "PATH": "/bin"}) == ["HTTPS_PROXY"]
    assert proxy.ambient_env({}) == []


# --------------------------------------------------------------------------- #
# args_for — the §2 matrix
# --------------------------------------------------------------------------- #
HTTP = proxy.parse("http://u:pw@h:8080")
HTTP_NOAUTH = proxy.parse("http://h:8080")
HTTPS = proxy.parse("https://h:8443")
SOCKS = proxy.parse("socks5://h:1080")
SOCKSH = proxy.parse("socks5h://u:pw@h:1080")


def test_args_for_flag_tools():
    assert HTTP.args_for("nuclei") == ["-proxy", "http://u:pw@h:8080", "-proxy-internal"]
    assert HTTP.args_for("ffuf") == ["-x", "http://u:pw@h:8080"]
    assert HTTP.args_for("katana") == ["-proxy", "http://u:pw@h:8080"]
    assert HTTP.args_for("subfinder") == ["-proxy", "http://u:pw@h:8080"]
    assert HTTP.args_for("curl") == ["--proxy", "http://u:pw@h:8080"]
    assert HTTP.args_for("wafw00f") == ["--proxy", "http://u:pw@h:8080"]
    assert HTTP.args_for("sqlmap") == ["--proxy", "http://h:8080", "--proxy-cred", "u:pw"]
    assert HTTP.args_for("sslyze") == ["--https_tunnel=http://u:pw@h:8080"]
    assert HTTP.args_for("whatweb") == ["--proxy", "h:8080", "--proxy-user", "u:pw"]
    assert HTTP_NOAUTH.args_for("whatweb") == ["--proxy", "h:8080"]
    assert HTTP_NOAUTH.args_for("nikto") == ["-useproxy", "http://h:8080"]
    assert HTTP.args_for("shcheck") == ["--proxy", "http://u:pw@h:8080"]
    assert HTTP.args_for("amass") == []


def test_args_for_socks5h_spelling_per_tool():
    # Go tools and sqlmap get "socks5" (remote resolution is Go's default);
    # curl / requests-based tools keep socks5h.
    assert SOCKSH.args_for("nuclei")[1] == "socks5://u:pw@h:1080"
    assert SOCKSH.args_for("ffuf") == ["-x", "socks5://u:pw@h:1080"]
    assert SOCKSH.args_for("sqlmap") == ["--proxy", "socks5://h:1080", "--proxy-cred", "u:pw"]
    assert SOCKSH.args_for("curl") == ["--proxy", "socks5h://u:pw@h:1080"]


@pytest.mark.parametrize("cfg,tool", [
    (HTTPS, "sslyze"), (SOCKS, "sslyze"),
    (HTTPS, "nikto"), (SOCKS, "nikto"), (HTTP, "nikto"),   # nikto: no proxy auth
    (HTTPS, "whatweb"), (SOCKS, "whatweb"),
    (HTTPS, "shcheck"),
    (HTTP, "headi"), (SOCKS, "headi"), (HTTPS, "headi"),
    (HTTP, "metis"), (SOCKS, "metis"),
    (HTTP, "findomain"),
    (HTTP, "no-such-tool"),
])
def test_args_for_unsupported_is_none(cfg, tool):
    assert cfg.args_for(tool) is None
    assert cfg.unsupported_reason(tool).startswith("proxy: ")


def test_shcheck_socks_supported():
    assert SOCKS.args_for("shcheck") == ["--proxy", "socks5://h:1080"]


def test_cli_is_shell_quoted():
    c = proxy.parse("http://u:a%27%3Bid@h:8080")  # password "a';id"
    s = c.cli("curl")
    import shlex
    assert shlex.split(s) == ["--proxy", c.url]
    assert "';id" not in s.replace("'\"'\"'", "")  # no raw unbalanced quote breakout


# --------------------------------------------------------------------------- #
# utils.run: env + redaction
# --------------------------------------------------------------------------- #
@pytest.fixture
def ev(tmp_path):
    events.reset()
    p = tmp_path / "events.jsonl"
    events.init(p)
    yield p
    events.reset()
    utils.set_secrets(())


def _events(p):
    return [json.loads(l) for l in p.read_text().splitlines()]


def test_run_redacts_cmd_output_and_sets_env(ev, capsys):
    c = proxy.parse("http://bob:s3cr3tpw@127.0.0.1:9")
    code = ("import os;print(os.environ.get('http_proxy'));"
            "print(repr(os.environ.get('NO_PROXY')));"
            "import sys;print(os.environ.get('HTTPS_PROXY'), file=sys.stderr);sys.exit(3)")
    cmd = f"{sys.executable} -c \"{code}\" --x {c.url}"
    with mock.patch.dict(os.environ, {"NO_PROXY": ".example.com"}):
        out = utils.run(cmd, timeout=30, proxy=c)
    # the child really saw the proxy env and a cleared NO_PROXY
    assert "http://bob:s3cr3tpw@127.0.0.1:9" in out
    assert "''" in out
    blob = ev.read_text() + capsys.readouterr().out
    assert "s3cr3tpw" not in blob
    assert "***" in blob
    outs = [e for e in _events(ev) if e["type"] == "output"]
    assert outs and all("s3cr3tpw" not in e["line"] for e in outs)


def test_run_without_proxy_leaves_env_untouched(ev):
    code = "import os;print(repr(os.environ.get('NO_PROXY')))"
    with mock.patch.dict(os.environ, {"NO_PROXY": ".keep"}):
        out = utils.run(f"{sys.executable} -c \"{code}\"", timeout=30)
    assert ".keep" in out


def test_global_secrets_redact_log_lines(ev, capsys):
    utils.set_secrets(("hunter2",))
    utils.warn("boom via http://u:hunter2@h:1")
    assert "hunter2" not in ev.read_text()
    assert "hunter2" not in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# fail-closed stage gating
# --------------------------------------------------------------------------- #
def _skip_reason_after(fn):
    with mock.patch.object(events, "mark_skipped") as ms, \
         mock.patch.object(utils, "run") as run, \
         mock.patch.object(utils, "warn"):
        out = fn()
    return out, ms, run


@pytest.mark.parametrize("name,call", [
    ("tls", lambda o, c: tls_scan.tls_scan("example.com", o, ["example.com"], proxy=c)),
    ("nikto", lambda o, c: nikto_scan.nikto_scan("example.com", o, ["example.com"], proxy=c)),
    ("tech", lambda o, c: tech_scan.tech_scan("example.com", o, ["example.com"], proxy=c)),
    ("metis", lambda o, c: metis_check.metis_check("example.com", o, ["example.com"], proxy=c)),
    ("headi", lambda o, c: headi_scan.headi_scan("example.com", o, [], proxy=c)),
])
def test_unproxyable_stages_skip_under_socks(tmp_path, name, call):
    with mock.patch.object(utils, "have", return_value=True):
        out, ms, run = _skip_reason_after(lambda: call(tmp_path, SOCKS))
    assert out == []
    run.assert_not_called()
    ms.assert_called_once()
    assert ms.call_args[0][0].startswith("proxy: ")


def test_headers_skipped_under_https_proxy_but_runs_under_socks(tmp_path):
    with mock.patch.object(http_headers, "_live_hosts", return_value=["example.com"]):
        out, ms, run = _skip_reason_after(
            lambda: http_headers.security_headers_scan("example.com", tmp_path, proxy=HTTPS))
        assert out == [] and ms.called and not run.called
        with mock.patch.object(utils, "run", return_value="{}") as run2, \
             mock.patch.object(utils, "log"):
            http_headers.security_headers_scan("example.com", tmp_path, proxy=SOCKS)
    cmd = run2.call_args[0][0]
    assert "--proxy socks5://h:1080" in cmd
    assert run2.call_args.kwargs["proxy"] is SOCKS


def test_supported_tools_get_flags(tmp_path):
    seen = []

    def fake_run(cmd, **kw):
        seen.append((cmd, kw.get("proxy")))
        return ""

    wl = tmp_path / "wl.txt"
    wl.write_text("a\n")
    with mock.patch.object(utils, "have", return_value=True), \
         mock.patch.object(utils, "run", side_effect=fake_run), \
         mock.patch.object(utils, "log"), mock.patch.object(utils, "warn"), \
         mock.patch.object(stages, "_resolve", return_value="93.184.216.34"), \
         mock.patch.object(waf_scan, "_resolve", return_value="93.184.216.34"), \
         mock.patch.object(api_endpoints, "_resolve", return_value="93.184.216.34"), \
         mock.patch.object(stages, "_patience_banner"):
        stages.vuln_scan("example.com", tmp_path, [{"host": "example.com", "status": 200}],
                         origins=[{"ip": "93.184.216.34"}], proxy=HTTP)
        stages.content_discovery("example.com", tmp_path, str(wl), proxy=HTTP)
        waf_scan.waf_scan("example.com", tmp_path, ["example.com"], proxy=HTTP)
        api_endpoints.api_endpoints_scan("example.com", tmp_path, ["example.com"], proxy=HTTP)
        param_scan.discover_endpoints("example.com", tmp_path, proxy=HTTP)
    joined = "\n".join(c for c, _ in seen)
    nuclei = [c for c, _ in seen if c.startswith("nuclei")]
    assert len(nuclei) == 2  # main + origin pass
    for c in nuclei:
        assert "-proxy http://u:pw@h:8080 -proxy-internal" in c
        assert "-ept" not in c  # owner decision: non-HTTP templates stay direct
    assert "-x http://u:pw@h:8080" in joined                 # ffuf
    assert "--proxy http://u:pw@h:8080" in joined            # wafw00f / curl
    assert "katana -u https://example.com" in joined and "-proxy http://u:pw@h:8080" in joined
    assert "curl --proxy http://u:pw@h:8080 -sS" in joined   # CDX
    assert all(p is HTTP for _, p in seen)


def test_sqlmap_gets_proxy_cred(tmp_path):
    seen = []
    with mock.patch.object(param_scan, "discover_endpoints", return_value=["https://e.com/?a=1"]), \
         mock.patch.object(utils, "have", return_value=True), \
         mock.patch.object(utils, "run", side_effect=lambda c, **kw: seen.append(c) or ""):
        param_scan.param_scan("e.com", tmp_path, proxy=HTTP)
    assert "--proxy http://h:8080 --proxy-cred u:pw" in seen[0]


def test_origin_verification_skipped_under_proxy(tmp_path):
    calls = []
    with mock.patch.object(stages, "_cloudflare_ranges", return_value=[__import__("ipaddress").ip_network("104.16.0.0/13")]), \
         mock.patch.object(stages, "_resolve", side_effect=lambda h: "93.184.216.34" if h.startswith("www.") else ""), \
         mock.patch.object(stages, "_mx_hosts", return_value=[]), \
         mock.patch.object(stages, "_verify_origin", side_effect=lambda *a: calls.append(a)), \
         mock.patch.object(utils, "log"), mock.patch.object(utils, "warn"):
        rows = stages.origin_hunt("example.com", tmp_path, {"ip": "104.16.1.1"}, proxy=HTTP)
    assert calls == []
    assert rows == [{"ip": "93.184.216.34", "sources": ["www.example.com"],
                     "status": stages.UNVERIFIED_PROXY, "remote_ip": ""}]


def test_origin_deep_verification_skipped_under_proxy(tmp_path):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return json.dumps([{"name_value": "a.example.com"}]) if "crt.sh" in cmd else ""

    with mock.patch.object(utils, "run", side_effect=fake_run), \
         mock.patch.object(stages, "_cloudflare_ranges", return_value=[__import__("ipaddress").ip_network("104.16.0.0/13")]), \
         mock.patch.object(stages, "_resolve", return_value="93.184.216.34"), \
         mock.patch.object(utils, "log"), mock.patch.object(utils, "warn"):
        rows = origin_deep.origin_deep("example.com", tmp_path, {}, proxy=HTTP)
    assert len(seen) == 1 and "--proxy http://u:pw@h:8080" in seen[0]
    assert rows[0]["status"] == stages.UNVERIFIED_PROXY


def test_subs_sub_tools_without_proxy_support_skip_without_marking_stage(tmp_path):
    from runner import subdomains
    with mock.patch.object(utils, "have", return_value=True), \
         mock.patch.object(utils, "run", return_value="") as run, \
         mock.patch.object(events, "mark_skipped") as ms, \
         mock.patch.object(utils, "warn"):
        assert subdomains.passive_findomain("example.com", tmp_path, proxy=HTTP) == set()
        subdomains.passive_subfinder("example.com", tmp_path, proxy=HTTP)
    ms.assert_not_called()
    assert len(run.call_args_list) == 1
    assert "-proxy http://u:pw@h:8080" in run.call_args[0][0]


# --------------------------------------------------------------------------- #
# CLI propagation
# --------------------------------------------------------------------------- #
def test_invalid_proxy_flag_exits_2(capsys):
    with pytest.raises(SystemExit) as e:
        cli.build_parser().parse_args(["example.com", "--proxy", "socks4://h:1"])
    assert e.value.code == 2


def test_invalid_env_proxy_exits_2(capsys):
    with mock.patch.dict(os.environ, {"BOUNTY_RUN_PROXY": "h:1"}):
        assert cli.main(["example.com", "--no-banner"]) == 2
    assert "BOUNTY_RUN_PROXY" in capsys.readouterr().err


def test_socks_gate_exits_2_without_pysocks(capsys):
    with mock.patch.object(proxy, "have_socks", return_value=False), \
         mock.patch.object(proxy, "preflight") as pf:
        assert cli.main(["example.com", "--no-banner", "--proxy", "socks5://h:1080"]) == 2
    pf.assert_not_called()
    assert "PySocks" in capsys.readouterr().err


def test_preflight_failure_exits_2_before_run_start(tmp_path, capsys):
    ev = tmp_path / "events.jsonl"
    with mock.patch.object(proxy, "preflight", return_value="cannot connect"), \
         mock.patch.object(cli, "_run") as run:
        rc = cli.main(["example.com", "--no-banner", "--events", str(ev),
                       "--proxy", "http://u:pw@h:8080"])
    assert rc == 2
    run.assert_not_called()
    assert not ev.exists()
    assert "preflight failed" in capsys.readouterr().err


def test_env_proxy_used_and_redacted_in_run_json(tmp_path):
    ev = tmp_path / "events.jsonl"
    with mock.patch.dict(os.environ, {"BOUNTY_RUN_PROXY": "socks5h://u:topsecret@h:1080"}), \
         mock.patch.object(proxy, "preflight", return_value=None) as pf, \
         mock.patch.object(cli, "_resolve_outdir", return_value=tmp_path), \
         mock.patch.object(cli, "_run", return_value=0) as run:
        assert cli.main(["example.com", "--no-banner", "--events", str(ev)]) == 0
    assert pf.call_args[0][0].redacted == "socks5h://u:***@h:1080"
    assert run.call_args[0][0].proxy == "socks5h://u:topsecret@h:1080"
    blob = (tmp_path / "run.json").read_text() + ev.read_text()
    assert "topsecret" not in blob
    assert json.loads((tmp_path / "run.json").read_text())["flags"]["proxy"] == "socks5h://h:1080"
    assert utils._secrets == ()  # cleared after the run


def test_ambient_proxy_env_warns_without_flag(tmp_path):
    with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://x:1"}), \
         mock.patch.object(cli, "_resolve_outdir", return_value=tmp_path), \
         mock.patch.object(cli, "_run", return_value=0), \
         mock.patch.object(utils, "warn") as w:
        os.environ.pop("BOUNTY_RUN_PROXY", None)
        cli.main(["example.com", "--no-banner"])
    assert any("half-proxied" in c[0][0] for c in w.call_args_list)


def _pipeline_args(extra):
    return cli.build_parser().parse_args(["example.com", "--nmap", *extra])


def test_pipeline_passes_proxy_to_http_stages_not_nmap(tmp_path):
    args = _pipeline_args(["--proxy", "http://h:8080", "--skip", "live,cf,origin,dork,secret,cors,panel"])
    st = cli.RunState("example.com")
    names = ["waf_scan.waf_scan", "nmap_scan.nmap_scan", "stages.vuln_scan",
             "stages.content_discovery", "api_endpoints.api_endpoints_scan",
             "param_scan.param_scan", "http_headers.security_headers_scan",
             "tech_scan.tech_scan", "stages.subdomain_enum"]
    patches = {}
    for n in names:
        mod, fn = n.split(".")
        patches[n] = mock.patch.object(getattr(cli, mod), fn, return_value=[])
    mocks = {n: p.start() for n, p in patches.items()}
    try:
        with mock.patch.object(cli, "write_summary"), mock.patch.object(cli.report, "write_findings_report"), \
             mock.patch.object(utils, "warn") as w:
            cli._pipeline(args, "example.com", tmp_path, set(args.skip.split(",")), st)
    finally:
        for p in patches.values():
            p.stop()
    for n in names:
        kw = mocks[n].call_args.kwargs
        if n == "nmap_scan.nmap_scan":
            assert "proxy" not in kw
        else:
            assert kw["proxy"].url == "http://h:8080", n
    assert any("DIRECT" in c[0][0] for c in w.call_args_list)


def test_pipeline_without_proxy_passes_no_proxy_kwarg(tmp_path):
    args = _pipeline_args(["--skip", "live,cf,origin,dork,secret,cors,panel"])
    with mock.patch.object(cli.waf_scan, "waf_scan", return_value=[]) as waf, \
         mock.patch.object(cli.stages, "subdomain_enum", return_value=["example.com"]) as se, \
         mock.patch.object(cli.nmap_scan, "nmap_scan", return_value=[]), \
         mock.patch.object(cli.stages, "vuln_scan", return_value=[]), \
         mock.patch.object(cli.stages, "content_discovery", return_value=[]), \
         mock.patch.object(cli.api_endpoints, "api_endpoints_scan", return_value=[]), \
         mock.patch.object(cli.param_scan, "param_scan", return_value=[]), \
         mock.patch.object(cli.http_headers, "security_headers_scan", return_value=[]), \
         mock.patch.object(cli.tech_scan, "tech_scan", return_value=[]), \
         mock.patch.object(cli, "write_summary"), mock.patch.object(cli.report, "write_findings_report"):
        cli._pipeline(args, "example.com", tmp_path, set(args.skip.split(",")), cli.RunState("example.com"))
    assert "proxy" not in waf.call_args.kwargs
    assert "proxy" not in se.call_args.kwargs


# --------------------------------------------------------------------------- #
# live loopback round-trip through a real SOCKS5 server
# --------------------------------------------------------------------------- #
class _Socks5(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, creds=None):
        self.creds = creds
        self.connects = []
        super().__init__(("127.0.0.1", 0), _SocksHandler)


class _SocksHandler(socketserver.BaseRequestHandler):
    def _recv(self, n):
        b = b""
        while len(b) < n:
            chunk = self.request.recv(n - len(b))
            if not chunk:
                raise ConnectionError
            b += chunk
        return b

    def handle(self):
        try:
            ver, n = self._recv(2)
            methods = self._recv(n)
            if self.server.creds:
                if 2 not in methods:
                    self.request.sendall(b"\x05\xff")
                    return
                self.request.sendall(b"\x05\x02")
                _, ulen = self._recv(2)
                u = self._recv(ulen)
                (plen,) = self._recv(1)
                p = self._recv(plen)
                ok = (u.decode(), p.decode()) == self.server.creds
                self.request.sendall(b"\x01\x00" if ok else b"\x01\x01")
                if not ok:
                    return
            else:
                self.request.sendall(b"\x05\x00")
            _, cmd, _, atyp = self._recv(4)
            if atyp == 1:
                host = socket.inet_ntoa(self._recv(4))
            elif atyp == 3:
                (ln,) = self._recv(1)
                host = self._recv(ln).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, self._recv(16))
            (port,) = struct.unpack("!H", self._recv(2))
            self.server.connects.append((host, port))
            up = socket.create_connection((host, port), timeout=5)
            self.request.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            socks = [self.request, up]
            while True:
                r, _, _ = select.select(socks, [], [], 5)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (up if s is self.request else self.request).sendall(data)
        except (ConnectionError, OSError, ValueError):
            pass


class _Web(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b"hello-through-proxy")

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture
def web():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Web)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def _socks(creds=None):
    srv = _Socks5(creds)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


needs_socks = pytest.mark.skipif(not proxy.have_socks(), reason="PySocks not installed")


@needs_socks
def test_live_curl_via_utils_run_goes_through_socks(web, ev):
    if not shutil.which("curl"):
        pytest.skip("curl not installed")
    srv = _socks(("alice", "pa:ss"))
    try:
        c = proxy.parse(f"socks5h://alice:pa%3Ass@127.0.0.1:{srv.server_address[1]}")
        url = f"http://localhost:{web.server_address[1]}/"
        out = utils.run(f"curl -sS --max-time 10{c.cli('curl')} {url}", timeout=30, proxy=c)
    finally:
        srv.shutdown()
    assert out == "hello-through-proxy"
    assert srv.connects == [("localhost", web.server_address[1])]  # remote DNS (socks5h)
    assert "pa:ss" not in ev.read_text() and "pa%3Ass" not in ev.read_text()


@needs_socks
def test_live_shcheck_socks_handler_goes_through_proxy(web):
    sys.path.insert(0, str(VENDOR))
    try:
        import importlib
        shcheck = importlib.import_module("shcheck")
    finally:
        sys.path.remove(str(VENDOR))
    srv = _socks()
    try:
        opener = shcheck.build_opener(f"socks5://127.0.0.1:{srv.server_address[1]}", True)
        r = opener.open(f"http://127.0.0.1:{web.server_address[1]}/", timeout=10)
        body = r.read()
    finally:
        srv.shutdown()
        import urllib.request
        urllib.request.install_opener(None)
    assert body == b"hello-through-proxy"
    assert srv.connects == [("127.0.0.1", web.server_address[1])]


@needs_socks
def test_live_preflight_ok_and_dead_proxy(web):
    srv = _socks(("u", "p"))
    target = f"127.0.0.1:{web.server_address[1]}"
    try:
        ok = proxy.parse(f"socks5h://u:p@127.0.0.1:{srv.server_address[1]}")
        assert proxy.preflight(ok, target, request_timeout=5) is None
        bad = proxy.parse(f"socks5h://u:WRONGPW@127.0.0.1:{srv.server_address[1]}")
        err = proxy.preflight(bad, target, request_timeout=5)
        assert err and "WRONGPW" not in err
    finally:
        srv.shutdown()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    err = proxy.preflight(proxy.parse(f"http://u:sekrit@127.0.0.1:{dead_port}"), target)
    assert err and "cannot connect to proxy" in err and "sekrit" not in err
