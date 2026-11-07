# Bounty Runner

A recon orchestrator that chains your arsenal into one sweep. Runs subdomain
enum, live-host probing, and Cloudflare detection — then (Phase 2+) hunts the
origin IP, scans for vulns, and produces a deduped report.

**Status:** Phase 2 — subdomain enum, live-host probe, Cloudflare detection, origin-IP hunting.

## Usage

```
bounty-run example.com                 # full sweep, output to ~/.bounty-run/
bounty-run example.com -o results/     # custom output dir
bounty-run example.com --amass         # also run amass passive enum
bounty-run example.com --timeout 5     # faster HTTP probe
bounty-run example.com --skip amass    # skip a stage (subs,live,cf)
```

## Output (per run)

```
~/.bounty-run/<target>/<timestamp>/
├── subfinder.txt      # raw subfinder output
├── subdomains.txt     # deduped subdomain list
├── live_hosts.txt     # host → status → server → CF flag
├── cloudflare.json    # Cloudflare detection result + evidence
└── SUMMARY.md         # human-readable summary
```

## Pipeline

1. Subdomain enum — `subfinder` (+ `amass` with `--amass`)
2. Live hosts — HTTP/HTTPS probe (status, server, Cloudflare flag)
3. Cloudflare detect — `cf-ray`/`server`/`cf-cache-status` headers + resolved IP
4. Origin hunt (when CF detected) — leak-subdomain sweep + MX records, filtered
   against Cloudflare's published AS13335 ranges, verified with `curl --resolve`

Phase 3 (next): crt.sh history + Shodan origin discovery, nuclei + SpyHunt + sqlmap,
and a deduped findings report.

## Notes

- Run only against targets you own or have written permission to test.
- `amass` passive enum needs API keys configured to return anything useful.
