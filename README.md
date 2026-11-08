# Bounty Runner

A recon orchestrator that chains your arsenal into one sweep. Runs subdomain
enum, live-host probing, and Cloudflare detection — then (Phase 2+) hunts the
origin IP, scans for vulns, and produces a deduped report.

**Status:** Phase 4 — recon→scan→report + deep origin discovery (crt.sh), param injection testing (sqlmap), and a SQLite findings tracker.

## Usage

```
bounty-run example.com                 # full sweep, output to <repo>/outputs/
bounty-run example.com -o results/     # custom output dir
bounty-run example.com --amass         # also run amass passive enum
bounty-run example.com --timeout 5     # faster HTTP probe
bounty-run example.com --skip param    # skip sqlmap (slow, active stage)
bounty-run example.com --max-param-urls 10   # cap sqlmap targets
bounty-run example.com --tls           # also run the sslyze TLS/SSL deep scan (opt-in, slow)
bounty-run example.com --nikto         # also run nikto web-server scan (opt-in, intrusive)
bounty-run example.com --skip dork     # skip passive search-engine dorking

# Findings tracker
bounty-run track add-target example.com --program "Acme Bug Bounty"
bounty-run track add-finding example.com --title "SQLi" --severity high --url "https://x/?id=1"
bounty-run track list --status new
bounty-run track update 1 --status submitted --bounty 500
bounty-run track stats
```

## Output (per run)

```
~/tools/bounty-run/outputs/<target>/<timestamp>/
├── subfinder.txt           # raw subfinder output
├── subdomains.txt          # deduped subdomain list
├── panels.txt              # cPanel/webmail/phpMyAdmin-style subdomains (<sub>\t<kind>\t<severity>)
├── live_hosts.txt          # host → status → server → CF flag
├── cloudflare.json         # Cloudflare detection result + evidence
├── origin_candidates.txt   # origin IPs behind Cloudflare (if any)
├── origin_deep.txt         # crt.sh deep-origin candidates
├── wafw00f.json            # raw wafw00f WAF fingerprint output
├── dork_urls.txt           # in-scope URLs found by Mojeek/DDG dorking
├── dork.txt                # per-request dork log (<query>\t<engine>\t<ok|blocked>\t<hits>)
├── sslyze/<host>.json      # raw sslyze JSON per host (--tls)
├── tls_scan.txt            # TLS issues (<host>\t<template>\t<severity>) (--tls)
├── nikto/<host>.json       # raw nikto JSON per host (--nikto)
├── nuclei.jsonl            # raw nuclei findings (JSONL)
├── content_discovery.txt   # ffuf-discovered paths
├── param_urls.txt          # parameterized URLs (Wayback CDX)
├── sqlmap_report.txt       # raw sqlmap output
├── findings.json           # deduped, structured findings
├── FINDINGS.md             # human-readable, severity-ordered report
└── SUMMARY.md              # run summary
```

## Pipeline

1. Subdomain enum — `subfinder` (+ `amass` with `--amass`)
2. Panel detection — flag cPanel/webmail/phpMyAdmin-style subdomains (no network)
3. Live hosts — HTTP/HTTPS probe (status, server, Cloudflare flag)
4. Cloudflare detect — `cf-ray`/`server`/`cf-cache-status` headers + resolved IP
5. Origin hunt (when CF detected) — leak-subdomain sweep + MX records, filtered
   against Cloudflare's published AS13335 ranges, verified with `curl --resolve`
6. Deep origin (when CF detected) — crt.sh cert-transparency SAN history, resolved
   and CF-filtered (Shodan/Censys documented as manual follow-up)
7. WAF fingerprint — `wafw00f` against live hosts (`waf:<name>` info findings)
8. Search-engine dorking — passive Mojeek/DuckDuckGo queries for exposed files
   and panels, results filtered to in-scope hosts
9. TLS/SSL analysis (`--tls`) — `sslyze` protocols, weak ciphers, Heartbleed,
   ROBOT, certificate checks per host (`tls:*` findings)
10. Web-server scan (`--nikto`) — `nikto` per host, bounded by `-maxtime`
    (`nikto:*` findings)
11. Vuln scan — `nuclei` against live hosts (`-jsonl`), parsed into findings
12. Content discovery — `ffuf` against the main target (auto-calibrated)
13. Param testing — Wayback CDX param discovery + `sqlmap` injection testing
14. Report — dedupe by (template, host), severity-ordered `FINDINGS.md` + `findings.json`

Phase 5 (next): interactive dashboard, SpyHunt automation.

## Notes

- Run only against targets you own or have written permission to test.
- `amass` passive enum needs API keys configured to return anything useful.
- Phase 12 external dependencies: `wafw00f` (WAF stage), `sslyze` (`--tls`),
  `nikto` (`--nikto`), and the Mojeek / DuckDuckGo HTML search endpoints
  (dork stage). Missing tools are skipped with a warning; if every search
  engine blocks the dork queries, a "blocked" warning is printed and dork
  results are incomplete.
