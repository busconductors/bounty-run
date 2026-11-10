"""Evidence capture: store request/response exchanges, build curl repros.

Findings reference evidence by the single fingerprint from :mod:`runner.finding`.
Everything is written under ``<run_dir>/evidence/`` with paths relative to the
run dir, so a run folder stays self-contained and movable. Secrets and auth
headers are redacted by default.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import threading
from pathlib import Path
from typing import Mapping

from . import finding

REDACT = {
    "authorization", "cookie", "set-cookie",
    "proxy-authorization", "x-api-key", "x-auth-token",
}

_TEXT_CONTENT_HINTS = ("text/", "json", "xml", "javascript", "html", "csv", "x-www-form")


def _header_items(headers):
    if headers is None:
        return []
    if isinstance(headers, Mapping):
        return list(headers.items())
    return list(headers)


def redact_headers(headers, redact: bool = True) -> list[tuple[str, str]]:
    """Return header (name, value) pairs, masking sensitive values when redacting."""
    out = []
    for k, v in _header_items(headers):
        if redact and str(k).lower() in REDACT:
            out.append((str(k), "<redacted>"))
        else:
            out.append((str(k), str(v)))
    return out


def _is_binary(body: bytes | None, content_type: str | None = None) -> bool:
    if content_type:
        ct = content_type.lower()
        if not any(h in ct for h in _TEXT_CONTENT_HINTS):
            return True
    if not body:
        return False
    return b"\x00" in body[:8192]


def build_curl(method, url, headers, body: bytes | None, *,
               redact: bool = True, insecure: bool = True) -> str:
    """Build a copy-pasteable curl command reproducing a request."""
    argv = ["curl", "-sS", "-i"]
    if insecure:
        argv.append("-k")
    if method and method.upper() != "GET":
        argv += ["-X", method.upper()]
    sent_ae = any(str(k).lower() == "accept-encoding" for k, _ in _header_items(headers))
    for k, v in redact_headers(headers, redact):
        argv += ["-H", f"{k}: {v}"]
    if sent_ae:
        argv.append("--compressed")
    if body:
        if _is_binary(body):
            argv += ["--data-binary", "@-"]
        else:
            argv += ["--data-raw", body.decode("utf-8", "replace")]
    argv.append(str(url))
    return shlex.join(argv)


def _as_bytes(data) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    return str(data).encode("utf-8", "replace")


class EvidenceStore:
    def __init__(self, run_dir, *, redact: bool = True, max_body: int = 256_000,
                 enabled: bool = True):
        self.run_dir = Path(run_dir)
        self.root = self.run_dir / "evidence"
        self.redact = redact
        self.max_body = max_body
        self.enabled = enabled
        self._index: dict[str, list[str]] = {}
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    # -- helpers ----------------------------------------------------------------

    def _next_dir(self, fp: str) -> tuple[str, Path]:
        with self._lock:
            n = self._counts.get(fp, 0) + 1
            self._counts[fp] = n
            evidence_id = f"{fp}-{n}"
            self._index.setdefault(fp, []).append(evidence_id)
        d = self.root / fp / str(n)
        d.mkdir(parents=True, exist_ok=True)
        return evidence_id, d

    def _rel(self, path: Path) -> str:
        return str(Path(path).relative_to(self.run_dir))

    def _write_body(self, directory: Path, name: str, body: bytes,
                    content_type: str | None) -> dict:
        binary = _is_binary(body, content_type)
        truncated = False
        if len(body) > self.max_body:
            body = body[: self.max_body]
            truncated = True
        meta = {
            "binary": binary,
            "truncated": truncated,
            "sha256_body": hashlib.sha256(body).hexdigest() if body else "",
        }
        if binary:
            (directory / (name + ".body.bin")).write_bytes(body)
            meta["body_file"] = name + ".body.bin"
        return meta, body

    def _write_repro(self, directory: Path, curl: str) -> Path:
        repro = directory / "repro.sh"
        repro.write_text("#!/bin/sh\nset -eu\n" + curl + "\n")
        os.chmod(repro, 0o700)
        return repro

    # -- public API -------------------------------------------------------------

    def record(self, request, response, *, finding: Mapping | None = None,
               note: str = "") -> str | None:
        """Store an in-process request/response exchange; return evidence_id."""
        if not self.enabled:
            return None
        f = finding or {}
        url = f.get("url") or getattr(response, "url", None) or getattr(request, "url", "")
        template = f.get("template") or ""
        host = f.get("host")
        fp = finding_fp(f) if finding else fp_from_url(template, host, url)
        evidence_id, directory = self._next_dir(fp)

        # request.http
        req_headers = redact_headers(getattr(request, "headers", {}), self.redact)
        method = getattr(request, "method", "GET") or "GET"
        req_body = _as_bytes(getattr(request, "body", None))
        req_lines = [f"{method} {url}"]
        req_lines += [f"{k}: {v}" for k, v in req_headers]
        req_text = "\r\n".join(req_lines) + "\r\n\r\n"
        if req_body:
            req_text += req_body.decode("utf-8", "replace")
        (directory / "request.http").write_text(req_text)

        # response.http
        resp_headers = redact_headers(getattr(response, "headers", {}), self.redact)
        status = getattr(response, "status_code", "")
        ctype = ""
        for k, v in resp_headers:
            if k.lower() == "content-type":
                ctype = v
        body = _read_body(response)
        body_meta, body = self._write_body(directory, "response", body, ctype)
        resp_lines = [f"HTTP {status}"]
        resp_lines += [f"{k}: {v}" for k, v in resp_headers]
        resp_text = "\r\n".join(resp_lines) + "\r\n\r\n"
        if not body_meta["binary"]:
            resp_text += body.decode("utf-8", "replace")
        (directory / "response.http").write_text(resp_text)

        curl = build_curl(method, url, getattr(request, "headers", {}), req_body,
                          redact=self.redact)
        self._write_repro(directory, curl)

        meta = {
            "evidence_id": evidence_id, "fingerprint": fp, "template": template,
            "host": host, "url": url, "status": status, "source": "inprocess",
            "redacted": sorted(REDACT) if self.redact else [], "note": note,
            "artifacts": [], **body_meta,
        }
        (directory / "meta.json").write_text(json.dumps(meta, indent=2))
        return evidence_id

    def record_raw(self, finding: Mapping, request_text, response_text,
                   curl: str | None = None, source: str = "nuclei") -> str | None:
        """Store raw request/response text (e.g. from nuclei jsonl)."""
        if not self.enabled:
            return None
        fp = finding_fp(finding)
        evidence_id, directory = self._next_dir(fp)
        (directory / "request.http").write_text(_redact_text(request_text, self.redact))
        (directory / "response.http").write_text(_redact_text(response_text, self.redact))
        if curl:
            self._write_repro(directory, curl)
        meta = {
            "evidence_id": evidence_id, "fingerprint": fp,
            "template": finding.get("template") or "", "host": finding.get("host"),
            "url": finding.get("url") or "", "source": source,
            "redacted": sorted(REDACT) if self.redact else [], "artifacts": [],
        }
        (directory / "meta.json").write_text(json.dumps(meta, indent=2))
        return evidence_id

    def link(self, finding: Mapping, paths, repro: str | None = None,
             note: str = "") -> str | None:
        """Link external tool artifacts to a finding by relative path."""
        if not self.enabled:
            return None
        fp = finding_fp(finding)
        evidence_id, directory = self._next_dir(fp)
        rels = []
        for p in paths:
            p = Path(p)
            if p.exists():
                try:
                    rels.append(self._rel(p))
                except ValueError:
                    rels.append(str(p))
        if repro:
            self._write_repro(directory, repro)
        meta = {
            "evidence_id": evidence_id, "fingerprint": fp,
            "template": finding.get("template") or "", "host": finding.get("host"),
            "url": finding.get("url") or "", "source": "tool",
            "artifacts": rels, "note": note,
        }
        (directory / "meta.json").write_text(json.dumps(meta, indent=2))
        return evidence_id

    def index(self) -> dict[str, list[str]]:
        with self._lock:
            return {k: list(v) for k, v in self._index.items()}

    def flush(self) -> None:
        if not self.enabled:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / "index.json.tmp"
        tmp.write_text(json.dumps(self.index(), indent=2))
        os.replace(tmp, self.root / "index.json")


def fp_from_url(template, host, url) -> str:
    return finding.fingerprint_of(template, host, url)


def finding_fp(f: Mapping) -> str:
    return finding.fingerprint_of(f.get("template"), f.get("host"), f.get("url"))


def _read_body(response) -> bytes:
    """Best-effort body read; empty for streamed/unconsumed responses."""
    try:
        return response.content or b""
    except Exception:  # noqa: BLE001 — streamed/closed responses
        return b""


def _redact_text(text, redact: bool) -> str:
    text = text or ""
    if not redact:
        return text
    out_lines = []
    for line in text.splitlines():
        head = line.split(":", 1)[0].strip().lower()
        if head in REDACT:
            name = line.split(":", 1)[0]
            out_lines.append(f"{name}: <redacted>")
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


# --- process-wide active store + in-process exchange stash --------------------

_active: EvidenceStore | None = None
_stash = threading.local()


def activate(store: EvidenceStore) -> None:
    global _active
    _active = store


def active() -> EvidenceStore | None:
    return _active


def reset() -> None:
    global _active
    _active = None
    if hasattr(_stash, "by_url"):
        _stash.by_url.clear()


def _stash_map() -> dict:
    if not hasattr(_stash, "by_url"):
        _stash.by_url = {}
    return _stash.by_url


def response_hook(resp, ctx) -> None:
    """httpclient response hook: stash the (request, response) by URL."""
    url = getattr(resp, "url", None) or getattr(getattr(resp, "request", None), "url", None)
    if url:
        _stash_map()[finding.normalize_url(url)] = (resp.request, resp)


def ingest_nuclei(store: EvidenceStore, outdir) -> int:
    """Parse ``nuclei*.jsonl`` and store each finding's raw request/response.

    Matches ``(template-id, host, matched-at)`` to the finding fingerprint and
    records the line's ``request``/``response``/``curl-command``. When ``-omit-raw``
    stripped those fields, the source jsonl is linked instead.
    """
    if store is None or not store.enabled:
        return 0
    outdir = Path(outdir)
    n = 0
    for jsonl in sorted(outdir.glob("nuclei*.jsonl")):
        for line in jsonl.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(j, dict):
                continue
            info = j.get("info") if isinstance(j.get("info"), dict) else {}
            f = {
                "severity": str(info.get("severity") or "unknown").lower(),
                "template": j.get("template-id", ""),
                "name": info.get("name", ""),
                "url": j.get("matched-at", ""),
                "host": j.get("host", ""),
            }
            request_text = j.get("request")
            response_text = j.get("response")
            curl = j.get("curl-command")
            if request_text or response_text:
                store.record_raw(f, request_text or "", response_text or "",
                                 curl=curl, source="nuclei")
            else:
                store.link(f, [jsonl], repro=curl, note="raw omitted (-omit-raw)")
            n += 1
    return n


# category key -> (artifact path templates, repro command template). ``{host}``
# is substituted per finding; ``{url}`` falls back to a plain curl.
_ARTIFACTS = {
    "nmap": (["nmap.xml", "nmap_open_ports.txt"], "nmap -sV {host}"),
    "nikto": (["nikto/{host}.json"], "nikto -host {host}"),
    "tls": (["sslyze/{host}.json"], "sslyze {host}"),
    "waf": (["wafw00f.json"], "wafw00f {url}"),
    "tech": (["whatweb.json"], "whatweb {url}"),
    "sqli": (["sqlmap_report.txt"], "sqlmap -u {url} --batch"),
    "headi": (["headi_raw.txt"], "headi -url {url}"),
    "headers_missing": (["security_headers.json"], "curl -sSI {url}"),
    "headers_insecure": (["security_headers.json"], "curl -sSI {url}"),
}


def link_tool_artifacts(store: EvidenceStore, findings, outdir) -> int:
    """Link external-tool artifact files to their findings, by category."""
    if store is None or not store.enabled:
        return 0
    from . import categories
    outdir = Path(outdir)
    linked = 0
    seen: set[str] = set()
    for f in findings:
        key = categories.classify(f.get("template")).key
        spec = _ARTIFACTS.get(key)
        if not spec:
            continue
        fp = finding_fp(f)
        if fp in seen:
            continue
        host = f.get("host") or ""
        url = f.get("url") or ""
        paths = [outdir / tmpl.format(host=host) for tmpl in spec[0]]
        existing = [p for p in paths if p.exists()]
        if not existing:
            continue
        repro = spec[1].format(host=host or url, url=url or host)
        store.link(f, existing, repro=repro)
        seen.add(fp)
        linked += 1
    return linked


def attach(finding_dict: Mapping, url: str | None = None) -> str | None:
    """Bind the most recent stashed exchange for ``url`` to a finding.

    No-op (returns None) if there is no active store or nothing stashed. Never
    mutates the finding dict.
    """
    store = _active
    if store is None:
        return None
    key = finding.normalize_url(url or finding_dict.get("url") or "")
    pair = _stash_map().get(key)
    if pair is None:
        return None
    request, response = pair
    return store.record(request, response, finding=finding_dict)
