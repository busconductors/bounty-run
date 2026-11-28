"""noauth recon stage: find unauthenticated web UIs / admin panels.

Adapted from noauth_finder (MIT License, (c) 2026 ek0mssavi0r). The corpus
constants and the auth-wall heuristic below are ported verbatim from that tool.
"""
import ipaddress
import json
import re

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
