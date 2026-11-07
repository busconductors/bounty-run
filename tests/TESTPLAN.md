# Bounty Runner — Manual Test Plan

The recon stages shell out to external tools (`subfinder`, `nuclei`, `ffuf`,
`dig`, `curl`) and hit live network targets, so they cannot be unit-tested.
This checklist covers the scenarios that matter for those stages. Run every
command from the project root:

```
cd ~/tools/bounty-run
```

`python3 bounty_run.py` is the entry point (wraps `runner.cli:main`). Replace
`example.com` below with a domain you own or are authorized to test. All
commands write output under the specified `-o` directory (or
`~/.bounty-run/<target>/<timestamp>` when `-o` is omitted).

## Prerequisites

- [ ] `subfinder`, `nuclei`, `ffuf`, `dig`, `curl` are on `PATH` (`which subfinder nuclei ffuf dig curl`).
- [ ] Python 3 with `requests` installed (used for live-host probing / CF detection).
- [ ] `nuclei` templates installed (`nuclei -update-templates`).

---

## 1. Cloudflare-fronted target

**Command:**

```
python3 bounty_run.py <cf-domain> -o /tmp/br-cf
```

**Expected result:**

- Exit code `0`.
- `cloudflare.json` has `"cloudflare": true` with at least one evidence entry
  (`cf-ray`, `server: cloudflare`, or `cf-cache-status present`).
- Console prints `[!] CLOUDFLARE DETECTED — ...`.
- `SUMMARY.md` shows `- Cloudflare on target: **YES**`.
- `origin_candidates.txt` exists (may be empty — see scenario 4).

---

## 2. Non-Cloudflare target

**Command:**

```
python3 bounty_run.py <plain-domain> -o /tmp/br-plain
```

**Expected result:**

- Exit code `0`.
- `cloudflare.json` has `"cloudflare": false`.
- Console prints `[+] no Cloudflare signatures found` (no `[!] CLOUDFLARE DETECTED`).
- `SUMMARY.md` shows `- Cloudflare on target: no`.
- The origin-hunt stage is skipped entirely: `origin_candidates.txt` is NOT
  created and no `Stage 4` line is logged.

---

## 3. Target with zero subdomains

**Command** (use a domain with no discoverable subdomains, e.g. a fresh test
domain, or force an empty enum by pointing `--skip live` and checking output):

```
python3 bounty_run.py <bare-domain> -o /tmp/br-nosubs
```

**Expected result:**

- Exit code `0` (no crash).
- `subdomains.txt` still exists and contains at least the bare target itself
  (the pipeline seeds `{target}` into the set before enum).
- Console: `1 subdomains -> subdomains.txt` (or "1" + however many enum found).
- Pipeline continues: `live_hosts.txt` probes just that single host;
  `nuclei_targets.txt` falls back to the bare target if no host responded.

---

## 4. Origin IP found vs not found

### 4a. Origin IP found

**Command** (against a Cloudflare-fronted target that leaks an origin via a
`mail.` / `direct.` / MX host):

```
python3 bounty_run.py <leaky-cf-domain> -o /tmp/br-origin-found
```

**Expected result:**

- `origin_candidates.txt` has one or more non-empty lines
  (`<ip>\t<http-status>\t<source1,source2>`).
- Console logs `N origin candidate(s)` and `origin candidates found — check ...`.
- Every listed IP is outside Cloudflare's AS13335 ranges (filtered).

### 4b. Origin IP not found

**Command** (against a fully-proxied CF domain):

```
python3 bounty_run.py <fully-proxied-cf-domain> -o /tmp/br-origin-none
```

**Expected result:**

- `origin_candidates.txt` exists but is empty (or contains only a newline).
- Console logs `0 origin candidate(s)` and
  `[!] no origin candidates surfaced — try crt.sh history + Shodan next`.

---

## 5. Nuclei timing out

**Command** (use `--skip subs,live,cf,origin,content` to isolate the vuln stage
against a slow/unreachable target, or point at a target that hangs):

```
python3 bounty_run.py <slow-domain> -o /tmp/br-nuclei-timeout --skip subs,live,cf,origin,content
```

**Expected result:**

- `nuclei` runs for up to 900s (its `utils.run` timeout). On timeout the
  console prints `[!]   timed out after 900s`.
- No exception is raised; the pipeline still completes and writes
  `findings.json` + `FINDINGS.md`.
- If `nuclei.jsonl` does not exist, `findings.json` is `[]` and
  `FINDINGS.md` shows `_No vulnerabilities found by nuclei._`.

---

## 6. ffuf soft-404 flooding

**Command** (against a target whose server returns HTTP 200 for every path,
e.g. a single-page app or a catch-all route — `-mc 200` will match everything):

```
python3 bounty_run.py <soft404-domain> -o /tmp/br-ffuf-flood --skip subs,live,cf,origin,vuln
```

**Expected result:**

- `ffuf` runs and `content_discovery.txt` is written, but it lists a huge
  number of near-identical 200 responses (the flood is captured raw, not
  deduped beyond path uniqueness).
- Console logs the (large) count: `N path(s) -> content_discovery.txt`.
- `FINDINGS.md` gains a `## Discovered content` section listing every path
  (sorted). NOTE: the CLI has no soft-404 filter today — the flood appears in
  the report as-is, which is the known limitation this scenario documents.
- Exit code `0` regardless of the flood size.

---

## Cross-cutting checks

- [ ] `findings.json` is valid JSON and sorted by severity
      (critical → high → medium → low → info → unknown).
- [ ] `FINDINGS.md` contains `# Findings — <target>` and, when findings exist,
      a `## Severity` count block and `## Vulnerabilities` entries.
- [ ] Duplicate `(template, host)` findings are collapsed (compare raw
      `nuclei.jsonl` line count vs `findings.json` entry count).
- [ ] `SUMMARY.md` always lists run time, subdomain count, live-host count, and
      Cloudflare status.
