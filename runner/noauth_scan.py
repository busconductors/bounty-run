"""noauth recon stage: find unauthenticated web UIs / admin panels.

Adapted from noauth_finder (MIT License, (c) 2026 ek0mssavi0r). The corpus
constants and the auth-wall heuristic below are ported verbatim from that tool.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from runner import events, httpclient, utils
from runner.stages import _is_global, _resolve

COMMON_WEB_PORTS = [
    80, 443, 8080, 8443, 8888, 9090, 3000, 5000,
    8000, 8001, 8081, 8444, 9000, 9001, 9200, 5601,
    7070, 7443, 9443, 10000, 1234, 4443, 9999, 8880,
    8082, 8083, 8084, 9002, 18080, 18081, 8889, 9091,
    7474, 7687, 5432, 3306, 27017, 15672, 15692, 3001,
    9092, 9990, 9991, 4848, 8686, 8834, 8333, 8123,
]

TOP10_PORTS = [80, 443, 8080, 8443, 8888, 9090, 3000, 5000, 8000, 9000]

# Ports that speak TLS first.
SSL_FIRST_PORTS = {443, 8443, 9443, 7443}

ADMIN_PATHS = [
    "/", "/login", "/admin", "/dashboard", "/panel",
    "/index.html", "/index.php", "/status", "/api/status",
    "/api/v1/status", "/api/health", "/health", "/healthz",
    "/manage", "/manager", "/console", "/admin/status",
    "/device", "/webui", "/cgi-bin/status",
]

CRITICAL_PATHS = [
    "/config", "/config.js", "/config.json", "/api/config",
    "/api", "/api/v1", "/graphql", "/status",
    "/logs", "/backup", "/backups", "/export",
    "/api/export", "/api/state", "/api/findings",
    "/api/creds", "/api/credentials", "/api/tokens",
    "/api/keys", "/api/endpoints", "/shell", "/cmd",
    "/api/cmd", "/api/command", "/api/execute",
    "/api/upload", "/api/files", "/api/query",
    "/api/exec", "/api/shell", "/terminal",
    "/proxy", "/api/proxy", "/api/run",
    "/prometheus", "/metrics", "/api/agent",
    "/deployment", "/environment", "/secrets",
    "/.env", "/api/control", "/dump", "/api/dump",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/v2/api-docs", "/v3/api-docs", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/metrics", "/actuator/configprops",
    "/debug", "/debug/vars",
]

SENSITIVE_PATH_HINTS = [
    "api/state", "api/control", "api/command", "api/exec",
    "shell", "cmd", "config", "secrets", "keys", "export",
    "dump", "api/creds", "api/findings", "terminal",
    ".env", "actuator/env", "v3/api-docs", "openapi",
    "graphql", "metrics",
]

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    r"(?i)aws_secret_access_key",
    r"(?i)secret[_-]?key",
    r"(?i)api[_-]?key",
    r"(?i)access[_-]?token",
    r"(?i)refresh[_-]?token",
    r"(?i)bearer\s+[a-z0-9._\-]{20,}",
    r"(?i)password\s*[:=]",
    r"(?i)passwd\s*[:=]",
    r"(?i)private[_-]?key",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)mongodb://",
    r"(?i)postgres://",
    r"(?i)mysql://",
    r"(?i)redis://",
    r"(?i)jdbc:",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
]

AUTH_STRONG_PATTERNS = [
    r"<input[^>]+type=[\"']?password",
    r"<form[^>]+(?:login|signin|auth)",
    r"(?:location\.href|window\.location)[^;\n]+login",
    r"http-equiv=[\"']refresh[\"'][^>]+login",
    r"www-authenticate",
]

AUTH_TEXT_HINTS = [
    "sign in", "signin", "log in", "login required",
    "authenticate", "unauthorized", "forbidden",
    "access denied", "credentials required",
    "enter password", "401 unauthorized", "403 forbidden",
]

NOAUTH_POSITIVE_HINTS = [
    "dashboard", "admin", "status", "metrics", "configuration",
    "settings", "system", "overview", "console", "management",
    "prometheus", "grafana", "jenkins", "kibana", "swagger",
    "api documentation", "server status", "health",
]

TECH_SIGNATURES = [
    ("Cockpit", ["cockpit"]),
    ("Kubernetes", ["kubernetes", "k8s"]),
    ("Grafana", ["grafana"]),
    ("Prometheus", ["prometheus"]),
    ("Jenkins", ["jenkins"]),
    ("phpMyAdmin", ["phpmyadmin"]),
    ("Adminer", ["adminer"]),
    ("Router/AP", ["router", "access point", "wifi settings"]),
    ("Camera/DVR", ["camera", "ip cam", "dvr", "nvr"]),
    ("NAS", ["nas", "synology", "qnap", "truenas", "freenas"]),
    ("Printer", ["printer", "hp eprint", "brother"]),
    ("C2 Panel", ["c2 ", "command & control", "command and control", "botnet", "agent panel"]),
    ("IoT Hub", ["smart home", "home assistant", "hassio"]),
    ("ESXi/vSphere", ["vmware esxi", "vsphere"]),
    ("Pi-hole", ["pi-hole", "pihole"]),
    ("OctoPrint", ["octoprint"]),
    ("Jellyfin", ["jellyfin"]),
    ("Plex", ["plex"]),
    ("Portainer", ["portainer"]),
    ("RabbitMQ", ["rabbitmq", "management"]),
    ("Elasticsearch", ["elasticsearch"]),
    ("OpenSearch", ["opensearch"]),
    ("Kibana", ["kibana"]),
    ("Nginx", ["nginx"]),
    ("Apache", ["apache"]),
    ("Syncthing", ["syncthing"]),
    ("Nextcloud", ["nextcloud"]),
    ("WordPress", ["wordpress", "wp-content", "wp-includes"]),
    ("Webmin", ["webmin"]),
    ("Netdata", ["netdata"]),
    ("Node-RED", ["node-red"]),
    ("Flask", ["flask"]),
    ("Node.js/Express", ["express", "node.js"]),
    ("Spring Boot Actuator", ["spring boot", "actuator", "actuator/env", "actuator/health"]),
    ("Swagger/OpenAPI", ["swagger", "openapi", "swagger-ui", "api-docs"]),
    ("SonarQube", ["sonarqube", "sonar"]),
    ("GitLab", ["gitlab"]),
    ("Harbor", ["harbor"]),
    ("Keycloak", ["keycloak"]),
    ("ArgoCD", ["argocd", "argo cd"]),
    ("Airflow", ["airflow"]),
    ("Traefik", ["traefik"]),
    ("Consul", ["consul"]),
    ("Vault", ["vault"]),
    ("MinIO", ["minio"]),
    ("Jupyter", ["jupyter", "notebook"]),
    ("Splunk", ["splunk"]),
    ("Nexus", ["nexus repository", "sonatype"]),
    ("Artifactory", ["artifactory", "jfrog"]),
]

HIGH_VALUE_TECH = {
    "Jenkins", "Kubernetes", "Grafana", "Prometheus", "phpMyAdmin",
    "Adminer", "Portainer", "RabbitMQ", "Elasticsearch", "OpenSearch",
    "Kibana", "Spring Boot Actuator", "Swagger/OpenAPI", "SonarQube",
    "GitLab", "Harbor", "Keycloak", "ArgoCD", "Airflow", "Consul",
    "Vault", "MinIO", "Jupyter", "Splunk", "Nexus", "Artifactory",
    "Webmin", "Node-RED"
}


def _check_auth(status, body_lower, headers, final_url=""):
    """True when the response is auth-walled (login/401/403/challenge)."""
    headers_lower = {str(k).lower(): str(v).lower() for k, v in headers.items()}

    if status in (401, 403):
        return True

    if "www-authenticate" in headers_lower:
        return True

    if final_url and re.search(r"/(?:login|signin|auth)(?:/|$|\?)", final_url.lower()):
        return True

    for pattern in AUTH_STRONG_PATTERNS:
        if re.search(pattern, body_lower, re.IGNORECASE):
            return True

    strong_hint_count = sum(1 for hint in AUTH_TEXT_HINTS if hint in body_lower)
    positive_hint_count = sum(1 for hint in NOAUTH_POSITIVE_HINTS if hint in body_lower)

    if strong_hint_count >= 2 and positive_hint_count == 0:
        return True

    return False


def _sensitive(body, headers=None):
    headers = headers or {}
    joined = (body or "")[:20000]
    hits = [p for p in SECRET_PATTERNS if re.search(p, joined)]
    content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    looks_json = "json" in content_type.lower() or joined.strip().startswith(("{", "["))
    stacktrace = bool(re.search(
        r"(?i)(traceback|exception|stack trace|java\.lang\.|at\s+[a-z0-9_.]+\()", joined))
    return {
        "secret_pattern_hits": len(hits),
        "looks_json": looks_json,
        "stacktrace": stacktrace,
    }


def _classify_tech(title, body, path, server, status, headers=None):
    text = f"{title} {body} {path} {server} {json.dumps(headers or {})}".lower()
    findings = []
    for name, keywords in TECH_SIGNATURES:
        if any(k.lower() in text for k in keywords):
            findings.append(name)
    return sorted(set(findings))


def is_private_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local
    except Exception:
        return False


def _severity_for(score):
    if score >= 60:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _score(host, port, response, tech, paths):
    score = 0
    reasons = []

    path_text = " ".join(paths).lower()
    title = (response.get("title") or "").lower()
    body = (response.get("body") or "").lower()
    url = response.get("url", "")
    sens = response.get("sensitive", {})

    if not is_private_ip(host):
        score += 15
        reasons.append("public_ip")

    if port not in (80, 443):
        score += 10
        reasons.append("nonstandard_web_port")

    if any(x in path_text for x in SENSITIVE_PATH_HINTS):
        score += 25
        reasons.append("sensitive_path_accessible")

    if sens.get("secret_pattern_hits", 0) > 0:
        score += 30
        reasons.append("secret_like_content")

    if sens.get("stacktrace"):
        score += 15
        reasons.append("stacktrace_detected")

    if sens.get("looks_json"):
        score += 8
        reasons.append("json_endpoint")

    if any(t in HIGH_VALUE_TECH for t in tech):
        score += 20
        reasons.append("high_value_admin_tech")

    if any(word in title + " " + body for word in ["dashboard", "admin", "console", "management"]):
        score += 10
        reasons.append("admin_or_dashboard_language")

    if url.endswith("/metrics") or "/metrics" in url:
        score += 10
        reasons.append("metrics_exposed")

    return score, _severity_for(score), reasons


# ---------------------------------------------------------------------------
# Stage orchestrator
# ---------------------------------------------------------------------------

_PROBE_TIMEOUT = 5
_MIN_SCORE = 20


def _port_paths() -> list[str]:
    """ADMIN_PATHS + CRITICAL_PATHS, deduped, order preserved."""
    return list(dict.fromkeys(ADMIN_PATHS + CRITICAL_PATHS))


def _extract_title(html):
    if not html:
        return ""
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return re.sub(r"\s+", " ", m.group(1).strip()) if m else ""


def _probe(host, port, path, ssl_enabled=None, timeout=_PROBE_TIMEOUT):
    """GET one path; a dict on any HTTP answer, else None. Never raises
    except for run cancellation."""
    if ssl_enabled is None:
        ssl_enabled = port in SSL_FIRST_PORTS
    url = f"{'https' if ssl_enabled else 'http'}://{host}:{port}{path}"
    try:
        r = httpclient.get(url, timeout=timeout, allow_redirects=True)
        text = r.text or ""
        headers = dict(r.headers)
        return {
            "status": r.status_code,
            "title": _extract_title(text),
            "server": headers.get("Server", ""),
            "body": text.lower()[:1000],
            "body_lower": text.lower()[:5000],
            "headers": headers,
            "url": url,
            "final_url": r.url or url,
            "ssl": ssl_enabled,
            "sensitive": _sensitive(text, headers),
        }
    except events.RunCancelled:
        raise
    except Exception as e:  # noqa: BLE001 — OutOfScope/timeouts/conn errors: unreachable
        # Upstream falls back https -> http on a TLS handshake failure only.
        if ssl_enabled and type(e).__name__ == "SSLError":
            return _probe(host, port, path, False, timeout)
        return None


def _category_of(path):
    p = path.lower()
    if "actuator" in p:
        return "actuator"
    if "metrics" in p:
        return "metrics"
    if any(k in p for k in ("config", ".env", "secret")):
        return "config"
    if "debug" in p:
        return "debug"
    if p.startswith("/api") or any(k in p for k in ("swagger", "graphql", "api-docs")):
        return "api"
    return "admin"


def _rep_key(item):
    path, resp = item
    sens = resp["sensitive"]
    return (sens["secret_pattern_hits"], sens["stacktrace"],
            any(h in path.lower() for h in SENSITIVE_PATH_HINTS))


def _scan_interface(host, port):
    """Probe every path on host:port; return a finding dict or None."""
    try:
        return _scan_interface_inner(host, port)
    except (events.RunCancelled, events.StageSkipped):
        raise
    except Exception as e:  # noqa: BLE001 — one bad interface must not sink the stage
        utils.warn(f"noauth failed for {host}:{port}: {e}")
        return None


def _scan_interface_inner(host, port):
    open_paths = []
    # Liveness gate only (not an auth gate): an unreachable "/" means a dead
    # port, so skip the other paths; a walled-but-reachable "/" still probes all.
    paths = _port_paths()
    for i, path in enumerate(paths):
        events.check_control()
        resp = _probe(host, port, path)
        if resp is None:
            if i == 0 and path == "/":
                return None
            continue
        # Precision guard: only 2xx responses are scored as exposed interfaces, so
        # terminal 401/403/404 and non-2xx error bodies (e.g. a 500 leaking a
        # stacktrace) are intentionally not emitted, to avoid flooding findings
        # on every live host.
        if not 200 <= resp["status"] < 300:
            continue
        if _check_auth(resp["status"], resp["body_lower"], resp["headers"],
                       resp["final_url"]) is False:
            open_paths.append((path, resp))
    if not open_paths:
        return None
    rep_path, rep = max(open_paths, key=_rep_key)
    tech = sorted({t for path, r in open_paths for t in _classify_tech(
        r["title"], r["body"], path, r["server"], r["status"], r["headers"])})
    score, severity, reasons = _score(host, port, rep, tech, [p for p, _ in open_paths])
    if score < _MIN_SCORE:
        return None
    category = _category_of(rep_path)
    return {
        "severity": severity,
        "template": f"noauth:{category}",
        "name": f"Unauthenticated {category} interface on {host}:{port}",
        "url": rep["final_url"],
        "host": host,
        "evidence": (f"score={score} {','.join(reasons)}; tech={tech}; "
                     f"open={[p for p, _ in open_paths]}"),
    }


def _norm_host(h):
    h = (h or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    return h.split("/", 1)[0].rstrip(".")


def _candidate_hosts(target, hosts, max_hosts):
    """Target + hosts, normalised, deduped, publicly routable, capped."""
    out, seen = [], set()
    for raw in [target, *(hosts or [])]:
        h = _norm_host(raw)
        if not h or h in seen:
            continue
        seen.add(h)
        if not _is_global(_resolve(h)):
            continue
        out.append(h)
        if len(out) >= max_hosts:
            break
    return out


def noauth_scan(target, outdir, hosts, max_hosts=20, ports=None, workers=4,
                proxy=None):
    """Find unauthenticated web interfaces; one finding per exposed host:port."""
    utils.log("noauth unauthenticated-interface scan")
    try:
        targets = _candidate_hosts(target, hosts, max_hosts)
    except Exception as e:  # noqa: BLE001
        utils.warn(f"noauth host collection failed: {e} — skipping")
        return []
    if not targets:
        utils.warn("no routable hosts — skipping noauth scan")
        return []

    ports = list(ports) if ports else list(TOP10_PORTS)
    units = [(h, p) for h in targets for p in ports]
    stage = events.current_stage() or "noauth"
    total = len(units)
    results = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_scan_interface, h, p): (h, p) for h, p in units}
        done = 0
        try:
            for fut in as_completed(futures):
                results[futures[fut]] = fut.result()
                done += 1
                events.progress(stage, done, total)
        except (events.RunCancelled, events.StageSkipped):
            pool.shutdown(wait=True, cancel_futures=True)
            raise

    findings = [results[u] for u in units if results.get(u)]
    utils.log(f"noauth: {len(findings)} exposed interface(s) across {len(targets)} host(s)")
    return findings
