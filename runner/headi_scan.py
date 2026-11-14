"""headi header-injection scan (Phase 7b, Feature 3)."""
import os
import re
import shutil
from pathlib import Path

from runner import proxy as proxymod
from runner import utils
from runner.stages import _is_global, _resolve

# Each line: [+-] [url] [Header: payload] [Code: N] [Size: N]
HEADI_RE = re.compile(
    r"^\[([+-])\] \[(.*?)\] \[([^:]+): (.*?)\] \[Code: (\d+)\] \[Size: (\d+)\]$"
)

# Host-header-injection-class headers -> high; everything else -> medium.
_HIGH_HEADERS = {"host", "x-forwarded-host", "x-http-host-override"}

# headi's -t flag is milliseconds; per-request timeout.
REQUEST_TIMEOUT_MS = 5000


def _read_live_hosts(path) -> list[str]:
    hosts = []
    for line in Path(path).read_text(errors="replace").splitlines():
        first = line.split("\t", 1)[0].strip()
        if first:
            hosts.append(first)
    return hosts


def _resolve_binary() -> str | None:
    env = os.environ.get("HEADI_BIN")
    if env and Path(env).exists():
        return env
    which = shutil.which("headi")
    if which:
        return which
    vendored = Path(__file__).resolve().parent / "vendor" / "bin" / "headi"
    if vendored.exists():
        return str(vendored)
    return None


def _hosts_from_rows(rows, outdir: Path, target: str) -> list[str]:
    if rows:
        hosts = [r.get("host") for r in rows if r.get("status")]
        hosts = [h for h in hosts if h]
        if hosts:
            return hosts
    live_path = Path(outdir) / "live_hosts.txt"
    if live_path.exists():
        hosts = _read_live_hosts(live_path)
        if hosts:
            return hosts
    return [target]


def headi_scan(target: str, outdir: Path, rows: list[dict] | None = None,
               timeout: int = 300, proxy=None) -> list[dict]:
    """Run headi against live hosts; return header-injection findings."""
    utils.log("header injection (headi)")
    # headi has no proxy option (static Go binary): fail-closed under --proxy.
    if not proxymod.gate(proxy, "headi"):
        return []
    binary = _resolve_binary()
    if not binary:
        utils.warn("headi binary not found (set HEADI_BIN) — skipping header-injection scan")
        return []

    hosts = [h for h in _hosts_from_rows(rows, outdir, target) if _is_global(_resolve(h))]
    if not hosts:
        utils.warn("no routable hosts — skipping header-injection scan")
        return []

    findings: list[dict] = []
    raw_lines: list[str] = []
    for host in hosts:
        url = f"https://{host}/"
        out = utils.run(f"{binary} -u {url} -t {REQUEST_TIMEOUT_MS}", timeout=timeout)
        raw_lines.append(f"# {url}")
        raw_lines.append(out)
        for line in out.splitlines():
            findings.extend(_parse_line(line, url, host))

    (Path(outdir) / "headi_raw.txt").write_text("\n".join(raw_lines))
    utils.log(f"headi: {len(findings)} finding(s) across {len(hosts)} host(s)")
    return findings


def _parse_line(line: str, url: str, host: str) -> list[dict]:
    m = HEADI_RE.match(line.strip())
    if not m:
        return []
    flag, _u, header, _payload, _code, _size = m.groups()
    if flag != "+":
        return []
    header_lc = header.lower()
    return [{
        "severity": "high" if header_lc in _HIGH_HEADERS else "medium",
        "template": f"headi:{header_lc}",
        "name": f"Header injection — {header}",
        "url": url,
        "host": host,
        "evidence": line.strip(),
    }]
