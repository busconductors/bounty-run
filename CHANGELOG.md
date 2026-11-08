# Changelog

All notable changes to Bounty Runner.

## Phase 13 — Interactive TUI

### 13a — engine events

- `--events PATH` writes a JSON-lines event stream (schema v1) plus `run.json`, `control` and `pids` in the run dir; plain CLI output is unchanged without it
- Events cover every stage, including `finding` events
- Control file: the TUI appends `skip <stage>` / `cancel` lines and the engine consumes them atomically; cancel writes a partial report and exits 130

### 13b — Go TUI core

- `tui/` bubbletea app (`make tui` → `bin/bounty-tui`) with Runs list and Monitor screens; event decoder and run-store
- Contract test: Python emitter ↔ Go decoder

### 13c — launch and control

- Launch form, detached engine spawn (`engine.log`), cap of 3 active runs (TUI-enforced)
- Skip / cancel with confirm, and hard kill via the recorded pgid when the engine stops responding
- Docs: README "Interactive TUI" section, TESTPLAN entries

## [1.1.0] — Phase 12

TLS depth, WAF fingerprinting, nikto, search-engine dorking, and admin-panel detection.

### Added

- **Panel detection** (default) — flags cPanel/webmail/phpMyAdmin-style subdomains from the enum list; writes `panels.txt`
- **WAF fingerprint** (default) — `wafw00f` against live hosts, one `waf:<name>` info finding per detected WAF; writes `wafw00f.json`
- **Search-engine dorking** (default) — passive Mojeek/DuckDuckGo dorks for exposed files and panels, in-scope filtered, warns when engines block; writes `dork_urls.txt` + `dork.txt`
- **TLS/SSL analysis** (opt-in `--tls`) — `sslyze` protocol/cipher/Heartbleed/ROBOT/certificate checks as `tls:*` findings; writes `sslyze/<host>.json` + `tls_scan.txt`
- **nikto web-server scan** (opt-in `--nikto`) — per-host `nikto` bounded by `-maxtime`, `nikto:*` findings; writes `nikto/<host>.json`

### Changed

- `TOTAL_STAGES` 15 → 20
- Report + dashboard gain buckets for panel/waf/dork/tls/nikto findings
- `--skip` accepts `panel,waf,dork,tls,nikto`

### Quality

- 311 unit tests (`python3 -m pytest -q`), up from 218

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
