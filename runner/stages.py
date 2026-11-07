"""Recon stages. Each stage reads prior output and writes its own artifacts."""
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import utils

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


def subdomain_enum(target: str, outdir: Path, skip_amass: bool = True) -> list[str]:
    """Stage 1: passive subdomain discovery via subfinder (+ optional amass)."""
    utils.log(f"Stage 1 — subdomain enumeration ({target})")
    subs = {target}

    if utils.have("subfinder"):
        txt = utils.run(f"subfinder -d {target} -silent",
                        outfile=str(outdir / "subfinder.txt"), timeout=300)
        for line in txt.splitlines():
            line = line.strip().lower()
            if line and not line.startswith(("#", "[", "-", "*")) and target in line:
                subs.add(line)
    else:
        utils.warn("subfinder not found — skipping")

    if not skip_amass and utils.have("amass"):
        txt = utils.run(f"amass enum -passive -d {target}",
                        outfile=str(outdir / "amass.txt"), timeout=300)
        for line in txt.splitlines():
            line = line.strip().lower()
            if line and target in line and not line.startswith(("#", "[", "-", "*")):
                subs.add(line)

    outfile = outdir / "subdomains.txt"
    outfile.write_text("\n".join(sorted(subs)) + "\n")
    utils.log(f"  {len(subs)} subdomains -> {outfile.name}")
    return sorted(subs)


def _probe_host(sub: str, timeout: int) -> dict:
    """Probe one host over HTTPS then HTTP; return its status row."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}"
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            server = r.headers.get("Server", "")
            is_cf = "cf-ray" in r.headers or "cloudflare" in server.lower()
            return {"host": sub, "url": r.url, "status": r.status_code,
                    "server": server, "cloudflare": is_cf}
        except Exception:  # noqa: BLE001
            continue
    return {"host": sub, "url": "", "status": 0, "server": "", "cloudflare": False}


def live_hosts(subdomains: list[str], outdir: Path, timeout: int = 8,
               threads: int = 30, max_hosts: int = 1000) -> list[dict]:
    """Stage 2: probe subdomains concurrently, record status + server + CF."""
    targets = subdomains[:max_hosts]
    utils.log(f"Stage 2 — probing {len(targets)} hosts ({threads} threads)")
    if not HAVE_REQUESTS:
        utils.warn("requests not available — skipping live-host probe")
        return []

    rows = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_probe_host, s, timeout): s for s in targets}
        for done, fut in enumerate(as_completed(futures), 1):
            rows.append(fut.result())
            if done % 500 == 0:
                utils.log(f"  ... probed {done}/{len(targets)}")

    rows.sort(key=lambda r: (r["status"] == 0, r["host"]))
    outfile = outdir / "live_hosts.txt"
    lines = [f"{r['host']}\t{r['status']}\t{r['server']}\t{'CF' if r['cloudflare'] else ''}" for r in rows]
    outfile.write_text("\n".join(lines) + "\n")
    live = [r for r in rows if r["status"]]
    utils.log(f"  {len(live)}/{len(rows)} responded -> {outfile.name}")
    return rows


def cloudflare_detect(target: str, outdir: Path) -> dict:
    """Stage 3: detect Cloudflare via response headers + resolved IP."""
    utils.log(f"Stage 3 — Cloudflare detection ({target})")
    result = {"target": target, "cloudflare": False, "evidence": []}
    try:
        result["ip"] = socket.gethostbyname(target)
    except Exception as e:  # noqa: BLE001
        result["ip"] = ""
        result["evidence"].append(f"DNS resolution failed: {e}")

    if HAVE_REQUESTS:
        try:
            r = requests.get(f"https://{target}", timeout=10, verify=False, allow_redirects=True)
            h = r.headers
            if "cf-ray" in h:
                result["cloudflare"] = True
                result["evidence"].append(f"cf-ray: {h['cf-ray']}")
            if "cloudflare" in h.get("Server", "").lower():
                result["cloudflare"] = True
                result["evidence"].append(f"server: {h.get('Server')}")
            if "cf-cache-status" in h:
                result["cloudflare"] = True
                result["evidence"].append("cf-cache-status present")
            result["status"] = r.status_code
        except Exception as e:  # noqa: BLE001
            result["evidence"].append(f"request error: {e}")

    outfile = outdir / "cloudflare.json"
    outfile.write_text(json.dumps(result, indent=2))
    if result["cloudflare"]:
        utils.warn(f"  CLOUDFLARE DETECTED — {'; '.join(result['evidence'])}")
    else:
        utils.log("  no Cloudflare signatures found")
    return result
