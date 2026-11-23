"""Origin-IP classification: is this IP dedicated to the target, or a shared edge?

Owning data alone cannot answer that (a target's own EC2 VM and Vercel's
anycast IP both belong to "Amazon"), so each candidate passes three layers,
run after the in-domain/CNAME filter in ``stages.origin_hunt``:

1. **Offline range lookup.** Providers' published range feeds (AWS, Google,
   Azure, Fastly, GitHub Pages, Oracle, Atlassian, Zendesk, Microsoft 365,
   DigitalOcean, Linode, mail SPF) plus a small built-in list for platforms
   that publish no feed (Vercel, Netlify, Shopify). An IP inside a shared
   front-end range is graded SHARED and never probed. AWS service ranges are
   subtracted from EC2: an IP in both EC2 and S3/CloudFront/Global
   Accelerator is SHARED, not tenant compute.
2. **ASN / WHOIS / rDNS** (iptoasn offline file, Team Cymru over DNS, RDAP).
   Recorded as metadata only. It never rejects an IP on its own; the one
   decisive positive is "the target holds this block" (prior OWN_NETWORK).
   A shared PTR (1e100.net, myshopify.com, ...) or an Akamai ASN marks SHARED.
3. **Active checks.** The response for the target via the IP is compared to
   the real site (baseline fetched through the CDN), the TLS certificate is
   read with SNI = target (Cloudflare Origin CA / non-provider SAN), and two
   negative controls (random Host+SNI, no SNI) make multi-tenant platforms
   identify themselves.

Tiers: CONFIRMED (only tier admitted into scan scope), LIKELY (manual
review), REJECTED (does not serve the site), SHARED (third-party front-end).

Feeds are cached in ``~/.cache/bounty-run/ipintel/`` (override with
``BOUNTY_RUN_IPINTEL_DIR``), offline-first: a run uses the cache and refreshes
only stale feeds, keeping the old copy when a refresh fails or looks
truncated. Fail-closed: when any shared-range feed is missing or older than
30 days, nothing grades above LIKELY.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
import re
import shlex
import socket
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

from . import proxy as proxymod
from . import utils

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
REJECTED = "REJECTED"
SHARED = "SHARED"
TIERS = (CONFIRMED, LIKELY, REJECTED, SHARED)
# Conservative merge order: when two sources disagree, the lower rank wins.
TIER_RANK = {SHARED: 0, REJECTED: 1, LIKELY: 2, CONFIRMED: 3}

OWN_NETWORK = "OWN_NETWORK"
TENANT_COMPUTE = "TENANT_COMPUTE"
UNKNOWN = "UNKNOWN"

DAY = 86400
WEEK = 7 * DAY
MAX_FEED_AGE = 30 * DAY  # older than this counts as missing (degraded)

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "bounty-run" / "ipintel"
# Generic browser UA: the Azure download page refuses curl's default UA.
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0 Safari/537.36")
MAX_BODY = 512_000


def cache_dir() -> Path:
    env = os.environ.get("BOUNTY_RUN_IPINTEL_DIR")
    return Path(env).expanduser() if env else DEFAULT_CACHE_DIR


# --------------------------------------------------------------------------
# Feed parsers: raw bytes -> [(cidr, provider, service)]. Data only, never
# executed. Each raises on a malformed payload so a bad refresh is rejected.
# --------------------------------------------------------------------------

def _json(raw: bytes):
    return json.loads(raw.decode("utf-8", "replace"))


def parse_aws(raw: bytes) -> list:
    j = _json(raw)
    out = [(p["ip_prefix"], "aws", p["service"]) for p in j["prefixes"]]
    out += [(p["ipv6_prefix"], "aws", p["service"]) for p in j.get("ipv6_prefixes", [])]
    return out


def _parse_google(service: str) -> Callable[[bytes], list]:
    def parse(raw: bytes) -> list:
        return [(p.get("ipv4Prefix") or p.get("ipv6Prefix"), "google", service)
                for p in _json(raw)["prefixes"]
                if p.get("ipv4Prefix") or p.get("ipv6Prefix")]
    return parse


parse_google_goog = _parse_google("goog")
parse_google_cloud = _parse_google("cloud")

# Only these Azure service tags matter; the regional AzureCloud.* copies are
# subsets of AzureCloud and would only bloat the table.
AZURE_TAGS = ("AzureFrontDoor.Frontend", "AppService", "AzureCloud")


def parse_azure(raw: bytes) -> list:
    out = []
    for v in _json(raw)["values"]:
        name = v.get("name", "")
        if name in AZURE_TAGS:
            out += [(c, "microsoft", name) for c in v["properties"]["addressPrefixes"]]
    return out


def parse_fastly(raw: bytes) -> list:
    j = _json(raw)
    return [(c, "fastly", "cdn") for c in j["addresses"] + j.get("ipv6_addresses", [])]


def parse_github(raw: bytes) -> list:
    return [(c, "github", "pages") for c in _json(raw)["pages"]]


def parse_oracle(raw: bytes) -> list:
    out = []
    for region in _json(raw)["regions"]:
        for c in region["cidrs"]:
            out += [(c["cidr"], "oracle", tag) for tag in c.get("tags", [])]
    return out


def parse_atlassian(raw: bytes) -> list:
    return [(it["cidr"], "atlassian", "ingress") for it in _json(raw)["items"]
            if "ingress" in (it.get("direction") or [])]


def parse_zendesk(raw: bytes) -> list:
    ingress = _json(raw)["ips"]["ingress"]
    return [(c, "zendesk", "ingress")
            for key in ("all", "specific") for c in ingress.get(key, [])]


def parse_m365(raw: bytes) -> list:
    return [(c, "microsoft", "m365") for e in _json(raw) for c in e.get("ips", [])]


def _parse_csv(provider: str, service: str) -> Callable[[bytes], list]:
    def parse(raw: bytes) -> list:
        out = []
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append((line.split(",", 1)[0].strip(), provider, service))
        return out
    return parse


parse_digitalocean = _parse_csv("digitalocean", "droplet")
parse_linode = _parse_csv("linode", "compute")


def parse_spf(raw: bytes) -> list:
    """Lines of ``<provider> <cidr>`` written by the SPF fetcher."""
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2:
            out.append((parts[1], parts[0], "spf"))
    return out


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    ttl: int
    parse: Callable[[bytes], list]
    shared: bool = True     # contributes SHARED ranges -> missing means degraded
    fetcher: str = "http"   # http | azure | m365 | spf
    headers: tuple = ()


FEEDS = (
    Feed("aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", DAY, parse_aws),
    Feed("google_goog", "https://www.gstatic.com/ipranges/goog.json", DAY, parse_google_goog),
    Feed("google_cloud", "https://www.gstatic.com/ipranges/cloud.json", DAY, parse_google_cloud),
    Feed("azure", "https://www.microsoft.com/en-us/download/details.aspx?id=56519",
         WEEK, parse_azure, fetcher="azure"),
    Feed("fastly", "https://api.fastly.com/public-ip-list", DAY, parse_fastly),
    Feed("github", "https://api.github.com/meta", DAY, parse_github,
         headers=("Accept: application/vnd.github+json",)),
    Feed("oracle", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
         WEEK, parse_oracle),
    Feed("atlassian", "https://ip-ranges.atlassian.com/", DAY, parse_atlassian),
    Feed("zendesk", "https://support.zendesk.com/ips", WEEK, parse_zendesk,
         headers=("Accept: application/json",)),
    Feed("m365", "https://endpoints.office.com/endpoints/worldwide", WEEK, parse_m365,
         fetcher="m365"),
    Feed("digitalocean", "https://digitalocean.com/geo/google.csv", WEEK,
         parse_digitalocean, shared=False),
    Feed("linode", "https://geoip.linode.com/", WEEK, parse_linode, shared=False),
    Feed("spf", "", WEEK, parse_spf, fetcher="spf"),
)
FEEDS_BY_NAME = {f.name: f for f in FEEDS}

IPTOASN_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
IPTOASN_TTL = WEEK

# Mail SPF roots -> provider. include: chains are followed (bounded).
SPF_ROOTS = {"_spf.google.com": "google", "spf.protection.outlook.com": "microsoft",
             "mail.zendesk.com": "zendesk"}

# Platforms with no range feed: documented single IPs (provider, service).
# Vercel 76.76.21.21 (its docs warn the per-project value can differ, which
# is why the fingerprint layer, not this list, is the real safety net),
# Netlify 75.2.60.5, Shopify 23.227.38.65, GitHub Pages apex IPs.
STATIC_SHARED = {
    "76.76.21.21/32": ("vercel", "apex"),
    "75.2.60.5/32": ("netlify", "apex"),
    "23.227.38.65/32": ("shopify", "storefront"),
    "185.199.108.153/32": ("github", "pages"),
    "185.199.109.153/32": ("github", "pages"),
    "185.199.110.153/32": ("github", "pages"),
    "185.199.111.153/32": ("github", "pages"),
    "2606:50c0:8000::153/128": ("github", "pages"),
    "2606:50c0:8001::153/128": ("github", "pages"),
    "2606:50c0:8002::153/128": ("github", "pages"),
    "2606:50c0:8003::153/128": ("github", "pages"),
}

# AWS services whose ranges are shared front-ends even where they overlap EC2.
AWS_SHARED = frozenset({
    "CLOUDFRONT", "CLOUDFRONT_ORIGIN_FACING", "GLOBALACCELERATOR", "S3",
    "API_GATEWAY", "ROUTE53", "ROUTE53_HEALTHCHECKS",
    "ROUTE53_HEALTHCHECKS_PUBLISHING", "ROUTE53_RESOLVER",
})
TENANT_PROVIDERS = frozenset({"digitalocean", "linode"})

# Akamai publishes no edge list; classify by ASN.
AKAMAI_ASNS = frozenset({12222, 16625, 16702, 17204})

# Provider -> apex domains it owns. Scanning the provider itself must not
# reject its own front-end as "shared".
PROVIDER_DOMAINS = {
    "aws": ("amazon.com", "amazonaws.com", "aws.amazon.com", "cloudfront.net"),
    "google": ("google.com", "googleapis.com", "gstatic.com", "youtube.com", "1e100.net",
               "googleusercontent.com"),
    "microsoft": ("microsoft.com", "office.com", "azure.com", "outlook.com", "live.com",
                  "azurewebsites.net", "azurefd.net"),
    "fastly": ("fastly.com", "fastly.net", "secretcdn.net"),
    "github": ("github.com", "github.io"),
    "oracle": ("oracle.com", "oraclecloud.com"),
    "atlassian": ("atlassian.com", "atlassian.net"),
    "zendesk": ("zendesk.com",),
    "vercel": ("vercel.com", "vercel.app", "vercel-infra.com"),
    "netlify": ("netlify.com", "netlify.app"),
    "shopify": ("shopify.com", "myshopify.com"),
    "heroku": ("heroku.com", "herokuapp.com"),
    "akamai": ("akamai.com", "akamaitechnologies.com", "akamaized.net"),
    "cloudflare": ("cloudflare.com", "cloudflaressl.com"),
    "digitalocean": ("digitalocean.com",),
    "linode": ("linode.com", "akamai.com"),
}


def _in_domain(name: str, domain: str) -> bool:
    n = (name or "").strip().lower().rstrip(".")
    d = (domain or "").strip().lower().rstrip(".")
    return bool(n) and bool(d) and (n == d or n.endswith("." + d))


def provider_self(target: str) -> set:
    """Providers that the target itself is (e.g. github.com -> {"github"})."""
    return {p for p, doms in PROVIDER_DOMAINS.items()
            if any(_in_domain(target, d) for d in doms)}


def _provider_of(name: str) -> str:
    for p, doms in PROVIDER_DOMAINS.items():
        if any(_in_domain(name, d) for d in doms):
            return p
    return ""


def categorise(labels) -> str | None:
    """Resolve the (provider, service) labels of every prefix containing an IP
    into ``SHARED:<provider>:<svc>`` / ``TENANT_COMPUTE:<provider>:<svc>`` /
    None. Shared wins over tenant (AWS: EC2 minus the service ranges; Google:
    goog minus cloud)."""
    by = defaultdict(set)
    for provider, service in labels:
        by[provider].add(service)
    shared, tenant = [], []
    for p, svcs in sorted(by.items()):
        if p == "aws":
            hit = sorted(svcs & AWS_SHARED)
            if hit:
                shared.append(f"aws:{hit[0]}")
            elif "EC2" in svcs:
                tenant.append("aws:EC2")
            else:  # provider-run service endpoint, or AMAZON-only space
                other = sorted(svcs - {"AMAZON"})
                shared.append(f"aws:{other[0] if other else 'AMAZON'}")
        elif p == "google":
            if "spf" in svcs:
                shared.append("google:spf")
            elif "cloud" in svcs:
                tenant.append("google:cloud")
            else:
                shared.append("google:goog")
        elif p == "microsoft":
            hit = sorted(svcs & {"AzureFrontDoor.Frontend", "m365", "spf"})
            if hit:
                shared.append(f"microsoft:{hit[0]}")
            elif "AppService" in svcs:
                tenant.append("microsoft:AppService(multi-tenant)")
            else:
                tenant.append(f"microsoft:{sorted(svcs)[0]}")
        elif p == "oracle":
            hit = sorted(svcs & {"OSN", "OBJECT_STORAGE"})
            if hit:
                shared.append(f"oracle:{hit[0]}")
            else:
                tenant.append(f"oracle:{sorted(svcs)[0]}")
        elif p in TENANT_PROVIDERS:
            tenant.append(f"{p}:{sorted(svcs)[0]}")
        else:
            shared.append(f"{p}:{sorted(svcs)[0]}")
    if shared:
        return f"{SHARED}:{shared[0]}"
    if tenant:
        return f"{TENANT_COMPUTE}:{tenant[0]}"
    return None


class RangeTable:
    """Exact prefix-membership lookup: one hash map per (version, prefixlen)."""

    def __init__(self):
        self._maps: dict = defaultdict(lambda: defaultdict(set))
        self.count = 0

    def add(self, cidr: str, label: tuple) -> bool:
        try:
            net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        except ValueError:
            return False
        self._maps[(net.version, net.prefixlen)][int(net.network_address)].add(label)
        self.count += 1
        return True

    def labels(self, ip: str) -> set:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return set()
        n, bits = int(a), a.max_prefixlen
        out = set()
        for (ver, plen), m in self._maps.items():
            if ver != a.version:
                continue
            key = (n >> (bits - plen)) << (bits - plen) if plen else 0
            out |= m.get(key, set())
        return out


# --------------------------------------------------------------------------
# Network primitives. Module-level so tests can replace them wholesale.
# --------------------------------------------------------------------------

def _fetch(url: str, dest: Path, proxy=None, headers=()) -> bool:
    """Download ``url`` to ``dest`` with curl; True when a non-empty file landed."""
    px = proxy.cli("curl") if proxy is not None else ""
    hdr = "".join(f" -H {shlex.quote(h)}" for h in headers)
    utils.run(f"curl -sS -f -L --connect-timeout 10 --max-time 120{px}{hdr} "
              f"-o {shlex.quote(str(dest))} {shlex.quote(url)}",
              timeout=150, **proxymod.run_kw(proxy))
    return dest.exists() and dest.stat().st_size > 0


def _dig_txt(name: str) -> list:
    """TXT strings for ``name`` (quotes stripped, multi-string records joined)."""
    if not utils.have("dig"):
        return []
    out = utils.run(f"dig +short +time=3 +tries=1 TXT {shlex.quote(name)}", timeout=15)
    recs = []
    for line in out.splitlines():
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        if parts:
            recs.append("".join(parts))
    return recs


def _bounded(fn, arg, timeout: float = 5.0):
    box = {}

    def worker():
        try:
            box["res"] = fn(arg)
        except BaseException as e:  # noqa: BLE001
            box["err"] = e
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive() or "err" in box:
        return None
    return box["res"]


def _ptr_lookup(ip: str) -> str:
    res = _bounded(socket.gethostbyaddr, ip)
    return res[0].lower().rstrip(".") if res else ""


def _rdap_fetch(ip: str, proxy=None) -> dict | None:
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / "rdap.json"
        if not _fetch(f"https://rdap.org/ip/{ip}", dest, proxy):
            return None
        try:
            return json.loads(dest.read_text(errors="replace"))
        except ValueError:
            return None


def _fetch_azure(feed: Feed, dest: Path, proxy) -> bool:
    """The Azure service-tag JSON link is dated; scrape it from the page."""
    with tempfile.TemporaryDirectory() as td:
        page = Path(td) / "page.html"
        if not _fetch(feed.url, page, proxy, (f"User-Agent: {BROWSER_UA}",)):
            return False
        m = re.search(r"https://download\.microsoft\.com/[^\"'\s]+/ServiceTags_Public_\d+\.json",
                      page.read_text(errors="replace"))
    return bool(m) and _fetch(m.group(0), dest, proxy, (f"User-Agent: {BROWSER_UA}",))


def _fetch_spf(dest: Path) -> bool:
    lines = []
    for root, provider in SPF_ROOTS.items():
        seen, queue = set(), [root]
        while queue and len(seen) < 30:
            name = queue.pop(0)
            if name in seen:
                continue
            seen.add(name)
            for rec in _dig_txt(name):
                if not rec.lower().startswith("v=spf1"):
                    continue
                for term in rec.split()[1:]:
                    term = term.lstrip("+?~-")
                    if term.startswith(("ip4:", "ip6:")):
                        lines.append(f"{provider} {term[4:]}")
                    elif term.startswith("include:"):
                        queue.append(term[8:])
    if not lines:
        return False
    dest.write_text("\n".join(lines) + "\n")
    return True


# --------------------------------------------------------------------------
# ASN / WHOIS parsing
# --------------------------------------------------------------------------

def parse_cymru_origin(records) -> dict | None:
    """Cymru origin TXT -> {asn, prefix, country, registry}; most specific
    prefix wins when several records come back. Multi-origin ASNs: first."""
    best = None
    for rec in records:
        f = [x.strip() for x in rec.split("|")]
        if len(f) < 2 or not f[0]:
            continue
        try:
            asn = int(f[0].split()[0])
            net = ipaddress.ip_network(f[1], strict=False)
        except ValueError:
            continue
        if best is None or net.prefixlen > best[1].prefixlen:
            best = ({"asn": asn, "prefix": str(net),
                     "country": f[2] if len(f) > 2 else "",
                     "registry": f[3] if len(f) > 3 else ""}, net)
    return best[0] if best else None


def parse_cymru_asname(records) -> str:
    for rec in records:
        f = [x.strip() for x in rec.split("|")]
        if len(f) >= 5 and f[4]:
            return f[4]
    return ""


def cymru_origin_name(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = a.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_iptoasn_line(line: str):
    """``start end asn country desc`` -> (start, end, asn|None, desc) or None.
    AS0 / "Not routed" yields asn None, never AS0."""
    f = line.rstrip("\n").split("\t")
    if len(f) < 3:
        return None
    try:
        start, end = ipaddress.ip_address(f[0]), ipaddress.ip_address(f[1])
        asn = int(f[2])
    except ValueError:
        return None
    desc = f[4] if len(f) > 4 else ""
    if asn == 0 or desc == "Not routed":
        return (start, end, None, "")
    return (start, end, asn, desc)


def parse_rdap(j: dict) -> str:
    """RDAP IP object -> "NETNAME / Registrant org" (block holder)."""
    if not isinstance(j, dict):
        return ""
    parts = [j.get("name") or ""]
    for ent in j.get("entities") or []:
        if "registrant" not in (ent.get("roles") or []):
            continue
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                parts.append(str(item[3]))
                break
    return " / ".join(p for p in parts if p)


_MULTI_SUFFIXES = ("co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
                   "co.za", "org.za", "co.nz", "co.jp", "com.br", "com.mx", "co.in",
                   "com.sg", "com.tr", "co.kr", "com.cn")


def brand(target: str) -> str:
    """Registrable label of the target ("shop.yoco.co.za" -> "yoco")."""
    labels = target.lower().rstrip(".").split(".")
    n = 3 if ".".join(labels[-2:]) in _MULTI_SUFFIXES else 2
    return labels[-n] if len(labels) >= n else labels[0]


def matches_target(target: str, *texts) -> bool:
    """True when the target's brand is a whole token in AS name / holder.
    Short brands (< 4 chars) are too ambiguous to count."""
    b = brand(target)
    if len(b) < 4:
        return False
    for t in texts:
        if t and b in re.split(r"[^a-z0-9]+", t.lower()):
            return True
    return False


SHARED_PTR = (
    re.compile(r"(^|\.)1e100\.net$"),
    re.compile(r"(^|\.)myshopify\.com$"),
    re.compile(r"(^|\.)cdn-[^.]*\.github\.com$"),
    re.compile(r"(^|\.)awsglobalaccelerator\.com$"),
    re.compile(r"(^|\.)cloudfront\.net$"),
    re.compile(r"(^|\.)akamaitechnologies\.com$"),
    re.compile(r"(^|\.)s3[a-z0-9-]*\.(.*\.)?amazonaws\.com$"),
)


def ptr_is_shared(ptr: str) -> bool:
    p = (ptr or "").lower().rstrip(".")
    return bool(p) and any(rx.search(p) for rx in SHARED_PTR)


# --------------------------------------------------------------------------
# The intel store
# --------------------------------------------------------------------------

class IpIntel:
    """Cached range feeds + ASN/holder/PTR metadata for one run."""

    def __init__(self, root: Path | None = None, *, proxy=None, offline: bool = False):
        self.root = Path(root) if root else cache_dir()
        self.proxy = proxy
        self.offline = offline
        self.table = RangeTable()
        self.missing: list = []          # shared feeds missing / too old
        self.feed_meta: dict = {}
        for cidr, label in STATIC_SHARED.items():
            self.table.add(cidr, label)
        self._asn: dict = {}
        self._last_rdap = 0.0
        self._meta_cache = self.root / "ipmeta.json"
        try:
            self._ipmeta = json.loads(self._meta_cache.read_text())
        except (OSError, ValueError):
            self._ipmeta = {}

    # -- loading -----------------------------------------------------------

    @classmethod
    def load(cls, root: Path | None = None, *, proxy=None, offline: bool = False,
             refresh: bool = False, now: float | None = None) -> IpIntel:
        intel = cls(root, proxy=proxy, offline=offline)
        intel._load_feeds(refresh=refresh, now=now or time.time())
        return intel

    @property
    def degraded(self) -> bool:
        return bool(self.missing)

    @property
    def online_dns(self) -> bool:
        """Per-IP DNS lookups to third parties (Cymru): skipped under --proxy
        (they would leave the proxy) and when offline."""
        return not self.offline and self.proxy is None

    def _feed_dir(self, name: str) -> Path:
        return self.root / name

    def _read_meta(self, name: str) -> dict:
        try:
            return json.loads((self._feed_dir(name) / "meta.json").read_text())
        except (OSError, ValueError):
            return {}

    def _load_feeds(self, refresh: bool, now: float) -> None:
        for feed in FEEDS:
            meta = self._read_meta(feed.name)
            raw = self._feed_dir(feed.name) / "raw"
            age = now - meta.get("fetched_at", 0) if raw.exists() else None
            stale = age is None or age > feed.ttl
            if not self.offline and (refresh or stale):
                if not self._refresh(feed, now):
                    if raw.exists():
                        utils.warn(f"  ipintel: refresh of {feed.name} failed — "
                                   "using the cached copy")
                    meta = self._read_meta(feed.name)
                else:
                    meta = self._read_meta(feed.name)
                    age = 0
            entries = []
            if raw.exists():
                try:
                    entries = feed.parse(raw.read_bytes())
                except Exception as e:  # noqa: BLE001
                    utils.warn(f"  ipintel: cached {feed.name} unreadable ({e})")
                    entries = []
            for cidr, provider, service in entries:
                self.table.add(cidr, (provider, service))
            self.feed_meta[feed.name] = {**meta, "loaded": len(entries)}
            if feed.shared and (not entries or age is None or age > MAX_FEED_AGE):
                self.missing.append(feed.name)
        if self.missing:
            utils.warn("  ipintel: missing/stale range feeds: "
                       f"{', '.join(self.missing)} — no origin can grade above LIKELY")

    def _refresh(self, feed: Feed, now: float) -> bool:
        """Download ``feed`` into its own dir; keep the old copy on failure or
        when the new one has fewer than half the prefixes (truncated / error
        page). Returns True when a new copy was installed."""
        d = self._feed_dir(feed.name)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / "raw.new"
        tmp.unlink(missing_ok=True)
        try:
            if feed.fetcher == "azure":
                ok = _fetch_azure(feed, tmp, self.proxy)
            elif feed.fetcher == "spf":
                ok = self.proxy is None and _fetch_spf(tmp)  # dig cannot use a proxy
            elif feed.fetcher == "m365":
                ok = _fetch(f"{feed.url}?clientrequestid={uuid.uuid4()}", tmp, self.proxy,
                            feed.headers)
            else:
                ok = _fetch(feed.url, tmp, self.proxy, feed.headers)
        except Exception as e:  # noqa: BLE001
            utils.warn(f"  ipintel: fetching {feed.name} raised {e}")
            ok = False
        if not ok or not tmp.exists():
            tmp.unlink(missing_ok=True)
            return False
        try:
            raw = tmp.read_bytes()
            entries = feed.parse(raw)
        except Exception:  # noqa: BLE001
            utils.warn(f"  ipintel: downloaded {feed.name} did not parse — kept old copy")
            tmp.unlink(missing_ok=True)
            return False
        old = self._read_meta(feed.name).get("prefix_count", 0)
        if not entries or (old and len(entries) < old / 2):
            utils.warn(f"  ipintel: downloaded {feed.name} has {len(entries)} prefixes "
                       f"(was {old}) — looks truncated, kept old copy")
            tmp.unlink(missing_ok=True)
            return False
        version = ""
        try:
            j = json.loads(raw)
            if isinstance(j, dict):
                version = str(j.get("syncToken") or j.get("changeNumber") or
                              j.get("creationTime") or "")
        except ValueError:
            pass
        tmp.replace(d / "raw")
        (d / "meta.json").write_text(json.dumps({
            "fetched_at": now, "url": feed.url, "prefix_count": len(entries),
            "version": version}))
        return True

    # -- lookups -----------------------------------------------------------

    def range_class(self, ip: str) -> str | None:
        return categorise(self.table.labels(ip))

    def _iptoasn_path(self) -> Path | None:
        d = self._feed_dir("iptoasn")
        path = d / "raw.tsv.gz"
        meta = self._read_meta("iptoasn")
        stale = not path.exists() or time.time() - meta.get("fetched_at", 0) > IPTOASN_TTL
        if stale and not self.offline:
            d.mkdir(parents=True, exist_ok=True)
            tmp = d / "raw.new.gz"
            tmp.unlink(missing_ok=True)
            if _fetch(IPTOASN_URL, tmp, self.proxy):
                try:
                    with gzip.open(tmp, "rt") as fh:
                        n = sum(1 for _ in fh)
                except (OSError, EOFError):
                    n = 0
                old = meta.get("prefix_count", 0)
                if n and not (old and n < old / 2):
                    tmp.replace(path)
                    (d / "meta.json").write_text(json.dumps(
                        {"fetched_at": time.time(), "url": IPTOASN_URL, "prefix_count": n}))
            tmp.unlink(missing_ok=True)
        return path if path.exists() else None

    def prefetch_asn(self, ips) -> None:
        """One streaming pass over the iptoasn file for all ``ips``."""
        want = {}
        for ip in ips:
            if ip in self._asn:
                continue
            try:
                want[ip] = ipaddress.ip_address(ip)
            except ValueError:
                continue
        if not want:
            return
        path = self._iptoasn_path()
        if path is None:
            return
        found = {}
        try:
            with gzip.open(path, "rt", errors="replace") as fh:
                for line in fh:
                    rec = parse_iptoasn_line(line)
                    if rec is None:
                        continue
                    start, end, asn, desc = rec
                    for ip, a in want.items():
                        if a.version == start.version and start <= a <= end:
                            found[ip] = {"asn": asn, "as_name": desc, "src": "iptoasn"}
                    if len(found) == len(want):
                        break
        except (OSError, EOFError):
            return
        self._asn.update(found)

    def asn(self, ip: str) -> dict:
        """{asn, as_name, src}; empty dict when unknown. Metadata only."""
        if ip in self._asn:
            return self._asn[ip]
        self.prefetch_asn([ip])
        if ip in self._asn:
            return self._asn[ip]
        info: dict = {}
        if self.online_dns:
            try:
                o = parse_cymru_origin(_dig_txt(cymru_origin_name(ip)))
            except ValueError:
                o = None
            if o:
                info = {"asn": o["asn"], "prefix": o["prefix"], "src": "cymru",
                        "as_name": parse_cymru_asname(_dig_txt(f"AS{o['asn']}.asn.cymru.com"))}
        self._asn[ip] = info
        return info

    def holder(self, ip: str) -> str:
        """RIR block holder via RDAP (cached per IP for a week; rate-limited)."""
        cached = self._ipmeta.get(ip, {})
        if "holder" in cached and time.time() - cached.get("ts", 0) < WEEK:
            return cached["holder"]
        if self.offline:
            return ""
        wait = 1.1 - (time.monotonic() - self._last_rdap)  # rdap.org: 10 req / 10 s
        if wait > 0:
            time.sleep(wait)
        self._last_rdap = time.monotonic()
        j = _rdap_fetch(ip, self.proxy)
        if j is None:
            return ""
        h = parse_rdap(j)
        self._ipmeta[ip] = {"holder": h, "ts": time.time()}
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            self._meta_cache.write_text(json.dumps(self._ipmeta))
        except OSError:
            pass
        return h

    def ptr(self, ip: str) -> str:
        return "" if self.offline else _ptr_lookup(ip)


# --------------------------------------------------------------------------
# Active probes (Layer 3)
# --------------------------------------------------------------------------

def _hostport(host_or_ip: str, port: int = 443) -> str:
    try:
        if ipaddress.ip_address(host_or_ip).version == 6:
            return f"[{host_or_ip}]:{port}"
    except ValueError:
        pass
    return f"{host_or_ip}:{port}"


def parse_headers(text: str) -> dict:
    """curl -D dump -> lower-cased header dict of the LAST response block."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", text) if b.strip()]
    out = {}
    if not blocks:
        return out
    for line in blocks[-1].splitlines()[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


def http_probe(host: str, ip: str | None = None, timeout: int = 12) -> dict:
    """GET https://<host>/ (pinned to ``ip`` when given; -k, no redirects).
    Returns {status, remote_ip, headers, body, error}."""
    with tempfile.TemporaryDirectory() as td:
        hdr, body = Path(td) / "h", Path(td) / "b"
        pin = ""
        if ip:
            pin_ip = f"[{ip}]" if ":" in ip else ip
            pin = f" --resolve {host}:443:{pin_ip}"
        out = utils.run(
            f"curl -sS -k --connect-timeout 10 --max-time {timeout} "
            f"-D {shlex.quote(str(hdr))} -o {shlex.quote(str(body))} "
            f"-w '%{{http_code}}|%{{remote_ip}}'{pin} https://{host}/",
            timeout=timeout + 8)
        parts = out.strip().split("|")
        headers = parse_headers(hdr.read_text(errors="replace")) if hdr.exists() else {}
        text = body.read_bytes()[:MAX_BODY].decode("utf-8", "replace") if body.exists() else ""
    return {"status": parts[0] if parts else "",
            "remote_ip": parts[1] if len(parts) > 1 else "",
            "headers": headers, "body": text, "error": ""}


def parse_x509_text(text: str) -> dict:
    """``openssl x509 -noout -subject -issuer -ext subjectAltName`` -> dict."""
    cert = {"subject": "", "issuer": "", "cn": "", "org": "", "sans": []}
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("subject="):
            cert["subject"] = s[len("subject="):].strip()
        elif s.startswith("issuer="):
            cert["issuer"] = s[len("issuer="):].strip()
        elif "DNS:" in s:
            cert["sans"] += [x.strip()[4:].lower() for x in s.split(",")
                             if x.strip().startswith("DNS:")]
    m = re.search(r"CN\s*=\s*([^,/]+)", cert["subject"])
    cert["cn"] = m.group(1).strip().lower() if m else ""
    m = re.search(r"(?:^|[,/]\s*)O\s*=\s*(\"[^\"]*\"|[^,/]+)", cert["subject"])
    cert["org"] = m.group(1).strip().strip('"') if m else ""
    return cert


def _client_cert_required(s_client_out: str) -> bool:
    t = s_client_out.lower()
    return "certificate required" in t or (
        "acceptable client certificate ca names" in t and "begin certificate" not in t)


def tls_cert(ip: str, servername: str | None = None) -> dict:
    """Leaf certificate presented by ``ip`` (SNI=servername, or none). Never
    verifies trust: an untrusted Origin CA cert is evidence, not a failure."""
    with tempfile.TemporaryDirectory() as td:
        raw = Path(td) / "s_client.txt"
        sni = f"-servername {shlex.quote(servername)}" if servername else "-noservername"
        utils.run(f"openssl s_client -connect {_hostport(ip)} {sni} </dev/null "
                  f"> {shlex.quote(str(raw))} 2>&1", timeout=20)
        text = raw.read_text(errors="replace") if raw.exists() else ""
        aop = _client_cert_required(text)
        if "BEGIN CERTIFICATE" not in text:
            return {"error": "client_cert_required" if aop else "no certificate",
                    "client_cert_required": aop, "subject": "", "issuer": "",
                    "cn": "", "org": "", "sans": []}
        out = utils.run(f"openssl x509 -in {shlex.quote(str(raw))} -noout -subject "
                        "-issuer -ext subjectAltName", timeout=10)
    cert = parse_x509_text(out)
    cert.update(error="", client_cert_required=aop)
    return cert


def control_probe(ip: str) -> dict:
    """Negative controls: random ``<uuid>.invalid`` Host+SNI, and the no-SNI cert."""
    bogus = f"{uuid.uuid4().hex}.invalid"
    return {"host": bogus, "http": http_probe(bogus, ip), "nosni_cert": tls_cert(ip, None)}


def baseline_probe(target: str) -> dict:
    """The real site, fetched normally (through the CDN)."""
    return http_probe(target, None)


# --------------------------------------------------------------------------
# Fingerprints + content comparison
# --------------------------------------------------------------------------

# (pattern, provider). A pattern starting with "*." matches that wildcard and
# any name under the suffix; otherwise an exact name.
PLATFORM_CERT_NAMES = (
    ("*.myshopify.com", "shopify"), ("*.github.io", "github"),
    ("fastly-pin-check.secretcdn.net", "fastly"), ("*.secretcdn.net", "fastly"),
    ("*.global.ssl.fastly.net", "fastly"),
    ("no-sni.vercel-infra.com", "vercel"), ("*.vercel-infra.com", "vercel"),
    ("*.vercel.app", "vercel"), ("*.netlify.app", "netlify"), ("*.netlify.com", "netlify"),
    ("*.herokuapp.com", "heroku"), ("*.herokudns.com", "heroku"),
    ("invalid2.invalid", "google"), ("*.googleusercontent.com", "google"),
    ("*.appspot.com", "google"), ("*.cloudfront.net", "aws"),
    ("*.s3.amazonaws.com", "aws"), ("*.elasticbeanstalk.com", "aws"),
    ("*.azurewebsites.net", "microsoft"), ("*.azurefd.net", "microsoft"),
    ("*.azureedge.net", "microsoft"), ("*.cloudflaressl.com", "cloudflare"),
    ("*.akamaized.net", "akamai"), ("a248.e.akamai.net", "akamai"),
    ("*.pantheonsite.io", "pantheon"), ("*.wpengine.com", "wpengine"),
    ("*.squarespace.com", "squarespace"), ("*.wixsite.com", "wix"),
    ("*.webflow.io", "webflow"), ("*.ghost.io", "ghost"), ("*.onrender.com", "render"),
    ("*.fly.dev", "fly"), ("*.zendesk.com", "zendesk"), ("*.atlassian.net", "atlassian"),
    ("*.hubspot.net", "hubspot"), ("*.hs-sites.com", "hubspot"),
)
PLATFORM_CERT_ORGS = (("netlify", "netlify"), ("heroku", "heroku"), ("shopify", "shopify"),
                      ("vercel", "vercel"), ("github", "github"), ("fastly", "fastly"))

# Header markers of a multi-tenant front-end answering an unknown Host.
PLATFORM_HEADERS = (
    ("x-vercel-error", "", "vercel"), ("x-nf-request-id", "", "netlify"),
    ("x-github-request-id", "", "github"), ("x-amz-cf-id", "", "aws"),
    ("x-azure-ref", "", "microsoft"), ("x-shopid", "", "shopify"),
    ("x-shopify-stage", "", "shopify"), ("fly-request-id", "", "fly"),
    ("x-render-origin-server", "", "render"), ("x-pantheon-styx-hostname", "", "pantheon"),
    ("x-wix-request-id", "", "wix"), ("cf-ray", "", "cloudflare"),
    ("x-served-by", "cache-", "fastly"), ("via", "heroku-router", "heroku"),
    ("server", "github.com", "github"), ("server", "vercel", "vercel"),
    ("server", "netlify", "netlify"), ("server", "heroku", "heroku"),
    ("server", "cloudflare", "cloudflare"), ("server", "akamaighost", "akamai"),
    ("server", "amazons3", "aws"), ("server", "cloudfront", "aws"),
    ("server", "gws", "google"), ("server", "google frontend", "google"),
    ("server", "squarespace", "squarespace"), ("server", "pepyaka", "wix"),
)

# "Unknown tenant" bodies (subdomain-takeover corpora: can-i-take-over-xyz,
# nuclei-templates http/takeovers).
TAKEOVER_BODIES = (
    ("No such app", "heroku"), ("There isn't a GitHub Pages site here", "github"),
    ("Sorry, this shop is currently unavailable", "shopify"),
    ("Not Found - Request ID:", "netlify"), ("Fastly error: unknown domain", "fastly"),
    ("404 error unknown site!", "pantheon"), ("The specified bucket does not exist", "aws"),
    ("NoSuchBucket", "aws"), ("DEPLOYMENT_NOT_FOUND", "vercel"),
    ("The deployment could not be found on Vercel", "vercel"),
    ("Error 404 (Not Found)!!1", "google"), ("404 Web Site not found", "microsoft"),
    ("Reference&#32;&#35;", "akamai"),
)


def _name_matches(name: str, pattern: str) -> bool:
    name = (name or "").lower().rstrip(".")
    if pattern.startswith("*."):
        return name == pattern or _in_domain(name.lstrip("*."), pattern[2:])
    return name == pattern


def cert_platform(cert: dict, own=frozenset()) -> str:
    """Provider whose wildcard/placeholder cert this is; "" if none."""
    if not cert:
        return ""
    names = [cert.get("cn", "")] + list(cert.get("sans") or [])
    for pattern, provider in PLATFORM_CERT_NAMES:
        if provider not in own and any(_name_matches(n, pattern) for n in names if n):
            return provider
    org = (cert.get("org") or "").lower()
    for marker, provider in PLATFORM_CERT_ORGS:
        if provider not in own and marker in org:
            return provider
    return ""


def response_platform(resp: dict, own=frozenset()) -> str:
    """Provider identified by a bogus-Host response's headers/body; ""."""
    if not resp:
        return ""
    h = resp.get("headers") or {}
    for name, needle, provider in PLATFORM_HEADERS:
        if provider in own or name not in h:
            continue
        v = h[name].lower()
        if not needle or (v.startswith(needle) if name == "x-served-by" else
                          (v == needle if name == "server" else needle in v)):
            return provider
    body = resp.get("body") or ""
    for needle, provider in TAKEOVER_BODIES:
        if provider not in own and needle in body:
            return provider
    return ""


def cert_is_origin_ca(cert: dict) -> bool:
    i = (cert or {}).get("issuer", "").lower()
    return "cloudflare" in i and "origin ssl" in i


def san_covers(cert: dict, target: str) -> bool:
    t = target.lower().rstrip(".")
    for n in [(cert or {}).get("cn", "")] + list((cert or {}).get("sans") or []):
        n = (n or "").lower().rstrip(".")
        if n == t:
            return True
        if n.startswith("*.") and t.endswith(n[1:]) and "." not in t[:-len(n) + 1]:
            return True
    return False


_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_ASSET = re.compile(r"""<(?:script|link|img)\b[^>]*?(?:src|href)\s*=\s*["']([^"'?#]+)""", re.I)
_NOISE = (
    re.compile(r"""\snonce\s*=\s*["'][^"']*["']""", re.I),
    re.compile(r"""(<input[^>]*type\s*=\s*["']hidden["'][^>]*value\s*=\s*)["'][^"']*["']""", re.I),
    re.compile(r"""(<meta[^>]*name\s*=\s*["']csrf[^"']*["'][^>]*content\s*=\s*)["'][^"']*["']""",
               re.I),
    re.compile(r"[A-Za-z0-9+/_=-]{24,}"),       # tokens, hashes, nonces
    re.compile(r"\d{2,}"),                      # timestamps, counters
)


def title_of(body: str) -> str:
    m = _TITLE.search(body or "")
    return re.sub(r"\s+", " ", m.group(1)).strip().lower() if m else ""


def assets_of(body: str) -> set:
    return set(_ASSET.findall(body or ""))


def normalise(body: str) -> str:
    s = body or ""
    for rx in _NOISE:
        s = rx.sub(lambda m: m.group(1) + '""' if m.groups() else "", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def similar(a: str, b: str) -> bool:
    """Same page? Exact after normalising out nonces/CSRF/tokens, else a
    tag-level similarity > 0.9 with matching titles, else same title and
    nearly the same asset set (dynamic pages)."""
    if not a or not b:
        return False
    na, nb = normalise(a), normalise(b)
    if na == nb:
        return True
    ta, tb = title_of(a), title_of(b)
    if ta != tb:
        return False
    sa, sb = re.split(r"(?=<)", na[:200_000]), re.split(r"(?=<)", nb[:200_000])
    if SequenceMatcher(None, sa, sb, autojunk=False).ratio() > 0.9:
        return True
    xa, xb = assets_of(a), assets_of(b)
    return bool(ta) and len(xa) >= 3 and len(xa & xb) / len(xa | xb) >= 0.8


def _status(resp: dict) -> int:
    try:
        return int(str((resp or {}).get("status", "")).strip() or 0)
    except ValueError:
        return 0


def _location(resp: dict) -> str:
    return ((resp or {}).get("headers") or {}).get("location", "").strip().rstrip("/").lower()


def ok_status(resp: dict, target: str) -> bool:
    """2xx, or a 3xx that stays on the target's own domain (or is relative)."""
    s = _status(resp)
    if 200 <= s < 300:
        return True
    if 300 <= s < 400:
        loc = _location(resp)
        if not loc or loc.startswith("/"):
            return True
        host = re.sub(r"^[a-z]+://", "", loc).split("/", 1)[0].split(":", 1)[0]
        return _in_domain(host, target)
    return False


def same_response(a: dict, b: dict) -> bool:
    """Do two responses show the same site? 3xx compare by Location."""
    sa, sb = _status(a), _status(b)
    if 300 <= sa < 400 or 300 <= sb < 400:
        return 300 <= sa < 400 and 300 <= sb < 400 and _location(a) == _location(b) != ""
    return similar((a or {}).get("body", ""), (b or {}).get("body", ""))


_CHALLENGE = ("just a moment...", "attention required! | cloudflare", "cf-chl",
              "challenge-platform", "/cdn-cgi/challenge")


def baseline_invalid(base: dict | None) -> str:
    """Why the baseline cannot be compared against; "" when usable."""
    if not base:
        return "no baseline"
    s = _status(base)
    body = (base.get("body") or "").lower()
    if (base.get("headers") or {}).get("cf-mitigated") or any(c in body for c in _CHALLENGE):
        return "baseline is a Cloudflare challenge page"
    if 300 <= s < 400:
        return "" if _location(base) else "baseline redirect without Location"
    if not (200 <= s < 300):
        return f"baseline status {s or 'none'}"
    if not body.strip():
        return "baseline body empty"
    return ""


# --------------------------------------------------------------------------
# The classifier
# --------------------------------------------------------------------------

@dataclass
class Verdict:
    tier: str
    reason: str = ""
    prior: str = UNKNOWN
    feed_class: str = ""
    asn: int | None = None
    as_name: str = ""
    holder: str = ""
    ptr: str = ""
    evidence: list = field(default_factory=list)

    def row(self) -> dict:
        d = asdict(self)
        d["evidence"] = "; ".join(self.evidence)
        return d


class Probe:
    """Bundle of Layer-3 probe callables (injectable for tests). Defaults are
    looked up at call time so module-level patches apply."""

    def __init__(self, target_http=None, control=None, cert=None, baseline=None):
        self._target_http = target_http
        self._control = control
        self._cert = cert
        self._baseline = baseline
        self.last_hit: dict = {}

    def target(self, ip: str, target: str) -> dict:
        fn = self._target_http or http_probe
        self.last_hit = fn(target, ip) or {}
        return self.last_hit

    def negative(self, ip: str) -> dict:
        return (self._control or control_probe)(ip) or {}

    def cert(self, ip: str, servername: str | None) -> dict:
        return (self._cert or tls_cert)(ip, servername) or {}

    def baseline(self, target: str) -> dict:
        return (self._baseline or baseline_probe)(target) or {}


def classify(ip: str, target: str, intel: IpIntel, baseline: dict | None = None,
             probe: Probe | None = None, *, unverified_reason: str = "") -> Verdict:
    """Grade one candidate IP. ``probe=None`` (e.g. --proxy) skips Layer 3:
    the best possible outcome is then LIKELY with ``unverified_reason``."""
    own = frozenset(provider_self(target))
    v = Verdict(tier=LIKELY)

    # Layer 1: offline range feeds.
    feed = intel.range_class(ip) or ""
    v.feed_class = feed
    feed_provider = feed.split(":")[1] if feed.count(":") >= 2 else ""
    if feed.startswith(SHARED) and feed_provider not in own:
        v.tier, v.reason = SHARED, f"range feed {feed[len(SHARED) + 1:]}"
        return v

    # Layer 2: metadata. Never rejects on ownership; one positive override.
    info = intel.asn(ip)
    v.asn, v.as_name = info.get("asn"), info.get("as_name", "")
    v.holder = intel.holder(ip)
    v.ptr = intel.ptr(ip)
    if (feed_provider and feed_provider in own) or matches_target(target, v.holder, v.as_name):
        v.prior = OWN_NETWORK
    elif feed.startswith(TENANT_COMPUTE):
        v.prior = TENANT_COMPUTE
    if v.prior != OWN_NETWORK:
        if v.asn in AKAMAI_ASNS and "akamai" not in own:
            v.tier, v.reason = SHARED, f"Akamai ASN AS{v.asn}"
            return v
        if ptr_is_shared(v.ptr) and _provider_of(v.ptr) not in own:
            v.tier, v.reason = SHARED, f"shared PTR {v.ptr}"
            return v

    if probe is None:
        v.tier, v.reason = LIKELY, unverified_reason or "not actively verified"
        return v

    # Layer 3a: negative controls make multi-tenant platforms identify themselves.
    ctrl = probe.negative(ip)
    fp = cert_platform(ctrl.get("nosni_cert") or {}, own)
    if fp:
        v.tier, v.reason = SHARED, f"no-SNI certificate is a {fp} platform certificate"
        return v
    ctrl_http = ctrl.get("http") or {}
    fp = response_platform(ctrl_http, own)
    if fp:
        v.tier, v.reason = SHARED, f"random-Host response fingerprints {fp}"
        return v

    # Layer 3b: the target via this IP.
    hit = probe.target(ip, target)
    cert = probe.cert(ip, target)
    if cert.get("client_cert_required") and v.prior == OWN_NETWORK:
        v.tier, v.reason = LIKELY, (
            "TLS demands a client certificate (Authenticated Origin Pulls) on the target's own network"
        )
        return v
    bad_base = baseline_invalid(baseline)
    if not ok_status(hit, target):
        v.tier, v.reason = REJECTED, f"target probe status {hit.get('status') or 'none'}"
        return v
    if not bad_base and not same_response(hit, baseline):
        v.tier, v.reason = REJECTED, "response differs from the real site"
        return v

    # Layer 3c/3d.
    origin_ca = cert_is_origin_ca(cert)
    san_ok = san_covers(cert, target) and not cert_platform(cert, own)
    distinct = not same_response(ctrl_http, hit)
    if origin_ca:
        v.evidence.append("Cloudflare Origin CA certificate")
    if san_ok:
        v.evidence.append("certificate SAN covers target (non-provider)")
    if distinct:
        v.evidence.append("random-Host response differs (not a catch-all)")
    if bad_base:
        v.evidence.append("content not compared")
    else:
        v.evidence.append("response matches the real site")
    if origin_ca or san_ok or distinct:
        v.tier, v.reason = CONFIRMED, "; ".join(v.evidence)
    else:
        v.tier, v.reason = LIKELY, "serves the site but TLS is ambiguous and the IP answers any Host"

    if v.tier == CONFIRMED:
        cap = ""
        if intel.degraded:
            cap = f"range feeds missing/stale ({', '.join(intel.missing)})"
        elif bad_base:
            cap = bad_base
        elif v.prior == UNKNOWN and not distinct and not origin_ca:
            cap = "unknown network with only SAN evidence"
        if cap:
            v.tier, v.reason = LIKELY, f"{v.reason} — capped: {cap}"
    return v


# --------------------------------------------------------------------------
# Run-level configuration (set by the CLI) + memoised loader
# --------------------------------------------------------------------------

_CONFIG = {"offline": False, "refresh": False}
_LOADED: dict = {}


def configure(*, offline: bool = False, refresh: bool = False) -> None:
    _CONFIG.update(offline=bool(offline), refresh=bool(refresh))
    _LOADED.clear()


def reset() -> None:
    configure()


def get(proxy=None) -> IpIntel:
    """The run's IpIntel (loaded once per process and config)."""
    key = (str(cache_dir()), _CONFIG["offline"], _CONFIG["refresh"], proxy is None)
    if key not in _LOADED:
        _LOADED[key] = IpIntel.load(proxy=proxy, offline=_CONFIG["offline"],
                                    refresh=_CONFIG["refresh"])
    return _LOADED[key]


def merge_rows(a: dict, b: dict) -> dict:
    """Most conservative tier wins when two stages graded the same IP."""
    ta, tb = a.get("tier"), b.get("tier")
    if tb and (not ta or TIER_RANK.get(tb, 0) < TIER_RANK.get(ta, 0)):
        keep = {k: b[k] for k in ("tier", "reason", "status", "remote_ip") if k in b}
        return {**a, **keep}
    return a


def scan_targets(origins) -> list:
    """Origin rows allowed into active scanning: CONFIRMED only. A row with no
    tier (legacy / unknown) is never admitted."""
    return [o for o in origins or []
            if isinstance(o, dict) and o.get("ip") and o.get("tier") == CONFIRMED]
