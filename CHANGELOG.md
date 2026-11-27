# Changelog

All notable changes to Bounty Runner are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.4.1] - 2026-11-27

### Fixed

- **macOS run supervision.** Scans now start, stream, show alive, and cancel
  cleanly on macOS (Apple Silicon), where the run-supervision code previously
  assumed Linux `/proc`:
  - The frozen engine read process start-time via a bare `ps`, which is not
    resolvable under the hardened PATH of the packaged app; it now calls
    `/bin/ps` by absolute path.
  - Launch liveness recorded a just-forked pid's start-time from a cached
    `ps` snapshot that could not yet see it, so a scan launched while another
    run was active was reported "engine exited before starting". `PIDStart`
    now reads fresh; per-OS `Alive` uses the snapshot with a fresh fallback on
    a cache miss, and memoises a confirmed death so a crashed run is not
    re-probed every refresh.
  - Cancel treated the macOS `EPERM` returned for an already-dead process
    group as a failure (Linux returns `ESRCH`); `HardKill` now tolerates it
    after a fresh liveness re-check, and the group-liveness check reads fresh
    so a just-spawned child group is never missed.
  - Linux behaviour is unchanged (its `/proc` path is build-tagged).

## [1.4.0] - 2026-11-26

### Added

- Easy install: `make install` plus an in-app Setup/Readiness screen (press `s`)
  that shows each external tool's status and installs the missing ones; a
  `bounty-run setup` engine command (hybrid go/pipx/apt); a soft warning before a
  scan when core tools are missing.

## [1.3.0] - 2026-11-25

### Changed

- The desktop app now ships from its own repository; public releases contain the
  engine and TUI only.

## [1.2.0] - 2026-11-23

Interactive TUI and origin-IP classification.

### Added

- **Engine event stream**: `--events PATH` writes a JSON-lines event stream (schema v1) plus `run.json`, `control` and `pids` in the run directory. Plain CLI output is unchanged without it
- Events cover every stage, including `finding` events
- **Control file**: the TUI appends `skip <stage>` / `cancel` lines and the engine consumes them atomically; cancel writes a partial report and exits 130
- **Interactive TUI** (`tui/`, bubbletea): `make tui` builds `bin/bounty-tui` with Runs list and Monitor screens, an event decoder and a run store
- Contract test between the Python event emitter and the Go decoder
- **Launch and control**: launch form, detached engine spawn (output captured in `engine.log`), and a cap of 3 active runs (enforced by the TUI)
- Skip and cancel with confirmation, and hard kill via the recorded process group when the engine stops responding
- README "Interactive TUI" section
- **Origin-IP classification** (`runner/ipintel.py`): each origin candidate is graded CONFIRMED / LIKELY / REJECTED / SHARED using provider range feeds, ASN/WHOIS/PTR metadata and active checks (content vs the real site, TLS certificate, random-Host and no-SNI negative controls)
- `--refresh-ipintel` and `--ipintel-offline` flags for the range-feed cache (`~/.cache/bounty-run/ipintel/`)

### Changed

- **Scope gate**: only CONFIRMED origin IPs are admitted into scope and passed to nmap/nuclei; everything else is reported for manual review. Under `--proxy` no origin is scanned
- Origin hunting now classifies every A record of a host, not just the first
- `origin_candidates.txt` / `origin_deep.txt` gain `tier` and `reason` columns; SHARED IPs appear as `#` comment lines

## [1.1.0] - Deeper scanning

TLS depth, WAF fingerprinting, nikto, search-engine dorking, and admin-panel detection.

### Added

- **Panel detection** (default): flags cPanel/webmail/phpMyAdmin-style subdomains from the enum list; writes `panels.txt`
- **WAF fingerprint** (default): `wafw00f` against live hosts, one `waf:<name>` info finding per detected WAF; writes `wafw00f.json`
- **Search-engine dorking** (default): passive Mojeek/DuckDuckGo dorks for exposed files and panels, in-scope filtered, warns when engines block; writes `dork_urls.txt` and `dork.txt`
- **TLS/SSL analysis** (opt-in `--tls`): `sslyze` protocol, cipher, Heartbleed, ROBOT and certificate checks as `tls:*` findings; writes `sslyze/<host>.json` and `tls_scan.txt`
- **nikto web-server scan** (opt-in `--nikto`): per-host `nikto` bounded by `-maxtime`, reported as `nikto:*` findings; writes `nikto/<host>.json`

### Changed

- The pipeline grows from 15 to 20 stages
- Report and dashboard gain buckets for panel, WAF, dork, TLS and nikto findings
- `--skip` accepts `panel,waf,dork,tls,nikto`
- Test suite expanded from 218 to 311 unit tests

## [1.0.0] - 2026-11-07

First stable release: a full recon, scan, report, track and dashboard pipeline.

### Added

- Subdomain enumeration (subfinder), concurrent live-host probe, Cloudflare detection
- Origin-IP hunting behind Cloudflare (leak subdomains and MX records, AS13335-filtered, verified with `curl --resolve`)
- nuclei vulnerability scan, ffuf content discovery, deduplicated findings report
- crt.sh deep-origin discovery, Wayback and sqlmap parameter testing
- SQLite findings tracker
- `--interactive` prompts, startup banner, HTML findings dashboard, severity colors, automatic tracker ingest

### Security

- 14 security and correctness fixes
- Command-injection and path-traversal protection (target allowlist), SSRF guard (`is_global`), scope check, and `html.escape` in the dashboard
- Fixed a SQL-injection false positive and a dedupe key bug; added `-k` for Cloudflare Origin CA certificates

### Changed

- Output moved to `<repo>/outputs/` (gitignored); tracker database co-located at `outputs/tracker.db`

### Quality

- 92 unit tests (stdlib `unittest`)
