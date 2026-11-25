"""Per-finding narrative metadata extracted from nuclei template info blocks."""
from __future__ import annotations

import json
from pathlib import Path

from .categories import classify
from .finding import fingerprint_of


def _str_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v not in (None, "")]
    return []


def _cvss(value) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_nuclei_narrative(outdir: Path) -> dict[str, dict]:
    """Map finding fingerprint -> description/reference/cvss/cwe from nuclei JSONL."""
    result: dict[str, dict] = {}
    for path in sorted(Path(outdir).glob("nuclei*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
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
            cls = info.get("classification")
            if not isinstance(cls, dict):
                cls = {}
            desc = info.get("description")
            fp = fingerprint_of(j.get("template-id", ""), j.get("host", ""),
                                j.get("matched-at", ""))
            result[fp] = {
                "description": desc if isinstance(desc, str) and desc else None,
                "reference": _str_list(info.get("reference")),
                "cvss": _cvss(cls.get("cvss-score")),
                "cwe": _str_list(cls.get("cwe-id")),
            }
    return result


# Generic per-category copy used when nuclei supplies no impact/remediation.
# Deliberately general: it describes the class of issue, not a specific exploit.
# "nuclei" is intentionally absent: unmatched nuclei templates cover arbitrary
# issue types, so no accurate generic text exists for them.
FALLBACK_COPY: dict[str, dict] = {
    "metis": {
        "impact": "Automated code review flagged a potential weakness in the application source. Exploitability depends on how the affected code is reached and must be confirmed manually.",
        "remediation": "Review the flagged code path, confirm whether the issue is reachable, and apply input validation, output encoding or access checks as appropriate.",
    },
    "secret": {
        "impact": "A credential or secret appears to be exposed to unauthenticated parties. If valid, it may allow unauthorized access to the services or data it protects.",
        "remediation": "Revoke and rotate the exposed secret, remove it from publicly served content and source history, and store secrets in a dedicated secrets manager.",
    },
    "sqli": {
        "impact": "User-controlled input appears to reach a database query unsanitized. An attacker may read or modify database contents and, in some configurations, execute commands on the database host.",
        "remediation": "Use parameterized queries or prepared statements for all database access, apply least-privilege database accounts, and validate input server-side.",
    },
    "headers_missing": {
        "impact": "The response omits a recommended HTTP security header. This weakens browser-side defenses and can make attacks such as clickjacking, content sniffing or script injection easier to carry out.",
        "remediation": "Configure the web server or application to send the missing header with a restrictive value suited to the application, and verify it on all responses.",
    },
    "headers_insecure": {
        "impact": "An HTTP security header is present but configured permissively. This reduces or removes the protection the header is intended to provide.",
        "remediation": "Tighten the header value in line with current guidance, remove unsafe directives, and verify the change does not break legitimate functionality.",
    },
    "cors": {
        "impact": "The cross-origin resource sharing policy permits untrusted origins. A malicious site may be able to read responses from the affected endpoint in the context of an authenticated user.",
        "remediation": "Restrict allowed origins to an explicit allow-list, do not reflect arbitrary origins or combine wildcard origins with credentials, and limit CORS to endpoints that need it.",
    },
    "headi": {
        "impact": "The application appears to trust or reflect client-supplied HTTP headers. This can enable cache poisoning, password-reset link manipulation, access-control bypass or request routing abuse.",
        "remediation": "Do not trust client-controlled headers such as Host or X-Forwarded-*. Validate them against a fixed allow-list and configure front-end proxies to overwrite them.",
    },
    "nmap": {
        "impact": "An open network service was identified. Each exposed service enlarges the attack surface and may be reachable by parties who do not need access to it.",
        "remediation": "Confirm the service is required, restrict access with firewall rules or network segmentation, keep the service patched, and disable it if unused.",
    },
    "tech": {
        "impact": "Technology and version information is disclosed. This is informational but can help an attacker select attacks matching known weaknesses in the identified components.",
        "remediation": "Keep identified components up to date and suppress unnecessary version banners and technology-revealing headers where practical.",
    },
    "api": {
        "impact": "An API endpoint was discovered. Endpoints that are undocumented, unauthenticated or insufficiently authorized can expose data or functionality beyond what is intended.",
        "remediation": "Inventory exposed endpoints, enforce authentication and object-level authorization on each, and remove or restrict endpoints that are not needed.",
    },
    "panel": {
        "impact": "An administrative or management interface is reachable. If it is weakly protected, it may allow unauthorized access to sensitive functionality or data.",
        "remediation": "Restrict the interface to trusted networks or VPN, enforce strong authentication with multi-factor where available, and remove it from public exposure if not required.",
    },
    "waf": {
        "impact": "A web application firewall was detected in front of the target. This is informational; it may filter some attacks but does not remove underlying application weaknesses.",
        "remediation": "No action required. Treat the WAF as a defense-in-depth layer and continue to fix vulnerabilities in the application itself.",
    },
    "dork": {
        "impact": "Search-engine queries surfaced content related to the target that may not be intended for public access, such as documents, configuration files or internal pages.",
        "remediation": "Review the indexed content, remove or restrict anything sensitive, and request de-indexing where appropriate. Use robots directives and access controls to prevent re-exposure.",
    },
    "tls": {
        "impact": "The TLS configuration has a weakness, such as a deprecated protocol, weak cipher or certificate problem. This may allow traffic to be intercepted or downgraded under certain conditions.",
        "remediation": "Disable deprecated protocols and weak ciphers, enable TLS 1.2 or later with modern cipher suites, and ensure certificates are valid, complete and correctly chained.",
    },
    "nikto": {
        "impact": "A web server scan reported a potential misconfiguration or exposed resource. The practical impact depends on the specific item and should be confirmed.",
        "remediation": "Verify the reported item, remove unnecessary files and default content, and harden the web server configuration according to vendor guidance.",
    },
}


def narrative_for(finding: dict, meta: dict | None) -> dict:
    """Assemble description/impact/remediation/reference/cvss/cwe for a finding.

    Nuclei metadata wins where present; impact and remediation (which nuclei
    rarely supplies) fall back to the finding's category copy, then to "".
    """
    meta = meta if isinstance(meta, dict) else {}
    template = finding.get("template") if isinstance(finding, dict) else None
    fb = FALLBACK_COPY.get(classify(template).key, {})
    return {
        "description": meta.get("description") or "",
        "impact": meta.get("impact") or fb.get("impact", ""),
        "remediation": meta.get("remediation") or fb.get("remediation", ""),
        "reference": list(meta.get("reference") or []),
        "cvss": meta.get("cvss"),
        "cwe": list(meta.get("cwe") or []),
    }
