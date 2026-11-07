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
├── live_hosts.txt          # host → status → server → CF flag
├── cloudflare.json         # Cloudflare detection result + evidence
├── origin_candidates.txt   # origin IPs behind Cloudflare (if any)
├── origin_deep.txt         # crt.sh deep-origin candidates
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
2. Live hosts — HTTP/HTTPS probe (status, server, Cloudflare flag)
3. Cloudflare detect — `cf-ray`/`server`/`cf-cache-status` headers + resolved IP
4. Origin hunt (when CF detected) — leak-subdomain sweep + MX records, filtered
   against Cloudflare's published AS13335 ranges, verified with `curl --resolve`
5. Deep origin (when CF detected) — crt.sh cert-transparency SAN history, resolved
   and CF-filtered (Shodan/Censys documented as manual follow-up)
6. Vuln scan — `nuclei` against live hosts (`-jsonl`), parsed into findings
7. Content discovery — `ffuf` against the main target (auto-calibrated)
8. Param testing — Wayback CDX param discovery + `sqlmap` injection testing
9. Report — dedupe by (template, host), severity-ordered `FINDINGS.md` + `findings.json`

Phase 5 (next): interactive dashboard, SpyHunt automation.

## Notes

- Run only against targets you own or have written permission to test.
- `amass` passive enum needs API keys configured to return anything useful.
