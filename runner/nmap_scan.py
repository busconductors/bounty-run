"""nmap port-scan stage (Phase 8).

Turns the IPs we already hold (live hosts + origin candidates + the target) into
service/port intelligence. Default: `-T4 -sS -sV -sC --top-ports 1000 --open`
(finishes in minutes); `full=True` opts into a full `-p-` scan.

Flow:
  1. Collect candidate IPs: resolve each live host in `rows`, each origin's `ip`,
     plus _resolve(target). Keep only publicly-routable IPs, dedupe, cap at 32.
  2. Run nmap once over all IPs, writing XML via -oX.
  3. Parse the XML and emit one finding per open port.

    from runner.nmap_scan import nmap_scan
    findings = nmap_scan("example.com", outdir, rows, origins)
"""
import xml.etree.ElementTree as ET
from pathlib import Path

from runner import events, utils
from runner.stages import _is_global, _resolve

# Ports whose exposure is worth a bump to low severity; everything else is info.
SENSITIVE_PORTS = {21, 22, 23, 25, 111, 139, 445, 1433, 2049, 3306, 5432, 5900,
                   5985, 5986, 6379, 9200, 9300, 11211, 27017, 27018, 2375, 2376, 3389}

# Bound runtime: never scan more than this many IPs in a single run.
MAX_IPS = 32


def _candidate_ips(target: str, rows: list[dict] | None,
                   origins: list[dict] | None) -> list[str]:
    """Public, deduped IPs from live hosts + origin candidates + the target."""
    ips: list[str] = []
    seen: set[str] = set()

    def add(ip: str) -> None:
        if ip and ip not in seen and _is_global(ip):
            seen.add(ip)
            ips.append(ip)

    for r in rows or []:
        if r.get("status"):
            host = r.get("host")
            if host:
                add(_resolve(host))
    for o in origins or []:
        add(o.get("ip") or "")
    add(_resolve(target))

    return ips[:MAX_IPS]


def nmap_scan(target: str, outdir: Path, rows: list[dict] | None = None,
              origins: list[dict] | None = None, timeout: int = 900,
              full: bool = False) -> list[dict]:
    """Run a medium-aggressive nmap scan over collected IPs; return port findings."""
    utils.log("nmap port scan")
    if not utils.have("nmap"):
        utils.warn("nmap not found — skipping port scan")
        events.mark_skipped("tool missing: nmap")
        return []

    ips = _candidate_ips(target, rows, origins)
    if not ips:
        utils.warn("no routable IPs — skipping port scan")
        return []

    xml_path = Path(outdir) / "nmap.xml"
    port_spec = "-p-" if full else "--top-ports 1000"
    utils.log(f"  scanning {len(ips)} IP(s) [-T4 -sS -sV -sC {port_spec}]")
    utils.run(
        f"nmap -T4 -sS -sV -sC {port_spec} --open -oX {xml_path} {' '.join(ips)}",
        timeout=timeout,
    )

    if not xml_path.exists():
        utils.warn("nmap produced no XML — skipping port scan")
        return []

    try:
        root = ET.fromstring(xml_path.read_text(errors="replace"))
    except ET.ParseError as e:
        utils.warn(f"nmap XML parse failed: {e} — skipping port scan")
        return []

    findings, raw_lines = _parse_hosts(root)
    (Path(outdir) / "nmap_open_ports.txt").write_text("\n".join(raw_lines) + "\n")
    utils.log(f"nmap: {len(findings)} open port(s) across {len(ips)} IP(s)")
    return findings


def _parse_hosts(root: ET.Element) -> tuple[list[dict], list[str]]:
    """Walk the nmap XML tree; return (findings, raw open-port lines)."""
    findings: list[dict] = []
    raw_lines: list[str] = []
    for host in root.findall("host"):
        ip = _host_ip(host)
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            f, raw = _port_finding(ip, port)
            findings.append(f)
            raw_lines.append(raw)
    return findings, raw_lines


def _host_ip(host: ET.Element) -> str:
    """Return the host's IPv4/IPv6 address (first address element as fallback)."""
    addrs = host.findall("address")
    for addr in addrs:
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr", "")
    return addrs[0].get("addr", "") if addrs else ""


def _port_finding(ip: str, port: ET.Element) -> tuple[dict, str]:
    """Build one finding + its greppable raw line from a `<port state=open>`."""
    portid = port.get("portid", "")
    proto = port.get("protocol", "")
    service = port.find("service")
    name = (service.get("name") if service is not None else "") or ""
    product = (service.get("product") if service is not None else "") or ""
    version = (service.get("version") if service is not None else "") or ""
    evidence = f"{product} {version}".strip()

    try:
        sensitive = int(portid) in SENSITIVE_PORTS
    except ValueError:
        sensitive = False

    finding = {
        "severity": "low" if sensitive else "info",
        "template": f"nmap:{portid}/{proto}",
        "name": f"Open port {portid}/{proto} — {name}",
        "url": ip,
        "host": ip,
        "evidence": evidence,
    }
    raw = f"{ip}:{portid}/{proto} {name} {version}".rstrip()
    return finding, raw
