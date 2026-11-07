# Changelog

All notable changes to Bounty Runner.

## [1.0.0] — 2026-11-07

First stable release — full recon → scan → report → track → dashboard pipeline.

### Phases 1–5 (feature build)

- **Phase 1** — subdomain enumeration (subfinder), concurrent live-host probe, Cloudflare detection
- **Phase 2** — origin-IP hunting behind Cloudflare (leak subdomains + MX, AS13335-filtered, `curl --resolve` verified)
- **Phase 3** — nuclei vulnerability scan, ffuf content discovery, deduped findings report
- **Phase 4** — crt.sh deep-origin discovery, Wayback + sqlmap param testing, SQLite findings tracker
- **Phase 5** — `--interactive` prompts, BuntyRun banner, HTML findings dashboard, severity colors, auto-track ingest

### Hardening

- 14 security/correctness fixes from an independent Claude Code cross-review
- Command-injection + path-traversal protection (target allowlist), SSRF guard (`is_global`), scope check, `html.escape` in dashboard
- SQL-injection false-positive fix, dedupe key fix, `-k` for Cloudflare Origin CA certs

### Quality

- 92 unit tests (stdlib `unittest`)
- gstack spec, audited by Claude Code (4/10 → 7/10 → resolved)

### Ops

- Output relocated to `<repo>/outputs/` (gitignored)
- Tracker DB co-located at `outputs/tracker.db`
