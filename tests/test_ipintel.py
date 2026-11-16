"""Origin-IP classification (runner.ipintel) and the CONFIRMED-only scope gate.

Hermetic: feeds come from trimmed fixtures in tests/fixtures/ipintel/, probes
are replayed from recorded fingerprints, and conftest.py stubs every network
primitive. The single live test is marked ``network`` and only runs with
BOUNTY_RUN_NETWORK_TESTS=1.
"""
import gzip
import ipaddress
import json
import os
import re
import shutil
import time
from pathlib import Path
from unittest import mock

import pytest

from runner import cli, ipintel, nmap_scan, origin_deep, proxy, scope, stages, utils

FIX = Path(__file__).resolve().parent / "fixtures" / "ipintel"
PROBES = json.loads((FIX / "probes.json").read_text())
PROBES.pop("_comment")

FEED_FIXTURES = {
    "aws": "aws.json", "google_goog": "goog.json", "google_cloud": "cloud.json",
    "azure": "azure.json", "fastly": "fastly.json", "github": "github.json",
    "oracle": "oracle.json", "atlassian": "atlassian.json", "zendesk": "zendesk.json",
    "m365": "m365.json", "digitalocean": "digitalocean.csv", "linode": "linode.csv",
    "spf": "spf.txt",
}
TARGET = "example.com"
CF_RANGES = [ipaddress.ip_network("104.16.0.0/13")]


def build_cache(root: Path, skip=(), age: float = 0.0, now: float | None = None) -> Path:
    """Populate an ipintel cache dir from the fixtures (fetched ``age`` s ago)."""
    now = now or time.time()
    for name, fname in FEED_FIXTURES.items():
        if name in skip:
            continue
        d = root / name
        d.mkdir(parents=True, exist_ok=True)
        raw = (FIX / fname).read_bytes()
        (d / "raw").write_bytes(raw)
        n = len(ipintel.FEEDS_BY_NAME[name].parse(raw))
        (d / "meta.json").write_text(json.dumps({"fetched_at": now - age, "prefix_count": n}))
    d = root / "iptoasn"
    d.mkdir(parents=True, exist_ok=True)
    with gzip.open(d / "raw.tsv.gz", "wt") as fh:
        fh.write((FIX / "ip2asn.tsv").read_text())
    (d / "meta.json").write_text(json.dumps({"fetched_at": now - age, "prefix_count": 7}))
    return root


@pytest.fixture
def intel(tmp_path):
    return ipintel.IpIntel.load(build_cache(tmp_path / "c"), offline=True)


# --- probe replay helpers --------------------------------------------------

SITE = ("<html><head><title>Example Corp</title><script src='/static/app.js'></script>"
        "<link href='/static/app.css'></head><body><h1>Welcome to Example Corp</h1>"
        "<input type='hidden' name='csrf' value='TOKEN-{n}'><p>Products, pricing and support.</p>"
        "</body></html>")
NGINX_DEFAULT = ("<html><head><title>Welcome to nginx!</title></head><body>"
                 "<h1>Welcome to nginx!</h1></body></html>")
ORIGIN_CA = {"subject": "O = \"CloudFlare, Inc.\", OU = CloudFlare Origin CA, CN = CloudFlare Origin Certificate",
             "issuer": "C = US, O = \"CloudFlare, Inc.\", OU = CloudFlare Origin SSL Certificate Authority, "
                       "L = San Francisco, ST = California",
             "cn": "cloudflare origin certificate", "org": "CloudFlare, Inc.",
             "sans": ["*.example.com", "example.com"], "client_cert_required": False}
LE_TARGET = {"subject": "CN = example.com", "issuer": "C = US, O = Let's Encrypt, CN = R11",
             "cn": "example.com", "org": "", "sans": ["example.com", "www.example.com"],
             "client_cert_required": False}
NO_CERT = {"error": "no certificate", "client_cert_required": False, "subject": "", "issuer": "",
           "cn": "", "org": "", "sans": []}


def resp(status="200", body="", headers=None):
    return {"status": status, "remote_ip": "", "headers": headers or {}, "body": body, "error": ""}


BASELINE = resp(body=SITE.format(n=1))


def make_probe(hit=None, target_cert=None, ctrl_http=None, nosni=None):
    calls = {"target": 0, "control": 0, "cert": 0}

    def target_http(host, ip):
        calls["target"] += 1
        return hit if hit is not None else resp(body=SITE.format(n=2))

    def control(ip):
        calls["control"] += 1
        return {"host": "x.invalid", "http": ctrl_http if ctrl_http is not None else resp("404", NGINX_DEFAULT),
                "nosni_cert": nosni if nosni is not None else NO_CERT}

    def cert(ip, servername):
        calls["cert"] += 1
        return target_cert if target_cert is not None else NO_CERT

    p = ipintel.Probe(target_http=target_http, control=control, cert=cert,
                      baseline=lambda t: BASELINE)
    p.calls = calls
    return p


# === Feed parsing / Layer 1 =================================================

@pytest.mark.parametrize("ip,expected", [
    ("75.2.60.5", "SHARED"),        # Netlify: EC2 ∩ GLOBALACCELERATOR (+ static list)
    ("75.2.1.1", "SHARED:aws:GLOBALACCELERATOR"),   # same prefix, not in static list
    ("3.80.0.10", "TENANT_COMPUTE:aws:EC2"),         # EC2-only prefix
    ("3.5.140.2", "SHARED:aws:S3"),                  # S3 ∩ EC2 -> subtraction rule
    ("52.94.0.1", "SHARED:aws:AMAZON"),              # AMAZON-only
    ("142.250.80.46", "SHARED:google:goog"),         # goog.json minus cloud.json
    ("34.64.0.5", "TENANT_COMPUTE:google:cloud"),    # cloud.json /20
    ("13.107.246.5", "SHARED:microsoft:AzureFrontDoor.Frontend"),
    ("13.64.1.1", "TENANT_COMPUTE:microsoft:AzureCloud"),
    ("20.40.202.5", "TENANT_COMPUTE:microsoft:AppService(multi-tenant)"),
    ("185.199.108.153", "SHARED:github:pages"),
    ("151.101.1.1", "SHARED:fastly:cdn"),
    ("76.76.21.21", "SHARED:vercel:apex"),
    ("23.227.38.65", "SHARED:shopify:storefront"),
    ("129.213.1.1", "TENANT_COMPUTE:oracle:OCI"),
    ("134.70.24.1", "SHARED:oracle:OBJECT_STORAGE"),
    ("104.192.136.1", "SHARED:atlassian:ingress"),
    ("13.52.5.97", None),                            # Atlassian egress only
    ("216.198.0.1", "SHARED:zendesk:ingress"),
    ("40.92.0.1", "SHARED:microsoft:m365"),
    ("35.190.247.1", "SHARED:google:spf"),
    ("104.131.1.1", "TENANT_COMPUTE:digitalocean:droplet"),
    ("45.33.1.1", "TENANT_COMPUTE:linode:compute"),
    ("198.51.100.10", None),
])
def test_feed_classification(intel, ip, expected):
    got = intel.range_class(ip)
    if expected is None or expected.count(":") >= 2:
        assert got == expected
    else:
        assert got.startswith(expected)


@pytest.mark.parametrize("ip,expected", [
    ("2600:1f18::10", "TENANT_COMPUTE:aws:EC2"),
    ("2600:9000::1", "SHARED:aws:CLOUDFRONT"),
    ("2607:f8b0::1", "SHARED:google:goog"),
    ("2600:1900:4000::1", "TENANT_COMPUTE:google:cloud"),
    ("2620:1ec:bdf::1", "SHARED:microsoft:AzureFrontDoor.Frontend"),
    ("2603:1000::1", "TENANT_COMPUTE:microsoft:AzureCloud"),
    ("2606:50c0:8000::153", "SHARED:github:pages"),
    ("2a04:4e40::1", "SHARED:fastly:cdn"),
    ("2603:1006::1", "SHARED:microsoft:m365"),
    ("2604:a880::1", "TENANT_COMPUTE:digitalocean:droplet"),
])
def test_ipv6_feed_classification(intel, ip, expected):
    assert intel.range_class(ip) == expected


def test_shared_feed_ip_is_never_probed(intel):
    p = make_probe()
    v = ipintel.classify("151.101.1.1", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.SHARED and "fastly" in v.reason
    assert p.calls == {"target": 0, "control": 0, "cert": 0}


def test_provider_self_target_is_not_rejected_as_shared(intel):
    p = make_probe(target_cert={**LE_TARGET, "cn": "github.com", "sans": ["github.com"]})
    v = ipintel.classify("185.199.108.153", "github.com", intel, BASELINE, p)
    assert v.tier != ipintel.SHARED
    assert v.prior == ipintel.OWN_NETWORK


# === ASN / WHOIS parsing (Layer 2) ==========================================

def test_cymru_two_records_most_specific_prefix_wins():
    recs = ["36459 | 140.82.112.0/20 | US | arin | 2017-01-12",
            "36459 | 140.82.112.0/24 | US | arin | 2017-01-12"]
    o = ipintel.parse_cymru_origin(recs)
    assert o["asn"] == 36459 and o["prefix"] == "140.82.112.0/24"
    assert ipintel.parse_cymru_origin(list(reversed(recs)))["prefix"] == "140.82.112.0/24"


def test_cymru_shopify_record_and_moas_first_asn():
    o = ipintel.parse_cymru_origin(["13335 | 23.227.38.0/23 | CA | arin | 2013-09-19"])
    assert (o["asn"], o["prefix"], o["country"]) == (13335, "23.227.38.0/23", "CA")
    assert ipintel.parse_cymru_origin(["30 10 20 | 192.0.2.0/24 | US | arin | "])["asn"] == 30
    assert ipintel.parse_cymru_origin(["garbage", ""]) is None


def test_cymru_asname_and_query_names():
    assert ipintel.parse_cymru_asname(
        ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"]
    ) == "CLOUDFLARENET - Cloudflare, Inc., US"
    assert ipintel.cymru_origin_name("23.227.38.65") == "65.38.227.23.origin.asn.cymru.com"
    assert ipintel.cymru_origin_name("2001:db8::1").endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")


def test_iptoasn_not_routed_yields_no_asn_not_as0():
    rec = ipintel.parse_iptoasn_line("100.64.0.0\t100.127.255.255\t0\tNone\tNot routed\n")
    assert rec[2] is None
    rec = ipintel.parse_iptoasn_line("3.80.0.0\t3.95.255.255\t14618\tUS\tAMAZON-AES\n")
    assert rec[2] == 14618 and rec[3] == "AMAZON-AES"


def test_iptoasn_offline_lookup(intel):
    assert intel.asn("3.80.0.10")["asn"] == 14618
    assert intel.asn("2600:1f18::10")["asn"] == 14618
    assert intel.asn("100.64.1.1")["asn"] is None


def test_rdap_holder_parse():
    j = {"name": "SHOPIFY-NET", "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                           ["fn", {}, "text", "Shopify, Inc."]]]},
        {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"]]]}]}
    assert ipintel.parse_rdap(j) == "SHOPIFY-NET / Shopify, Inc."


def test_matches_target_is_token_based():
    assert ipintel.brand("shop.yoco.co.za") == "yoco"
    assert ipintel.matches_target("examplecorp.com", "EXAMPLECORP-AS Example Corp")
    assert not ipintel.matches_target("examplecorp.com", "NOTEXAMPLECORPX")
    assert not ipintel.matches_target("abc.com", "ABC")  # too short to trust


def test_cloud_asn_alone_never_rejects(intel):
    # AWS-held, AWS-announced EC2 VM with an EC2 PTR: ownership says "Amazon",
    # which must not count against it.
    with mock.patch.object(ipintel, "_ptr_lookup", return_value="ec2-3-80-0-10.compute-1.amazonaws.com"):
        intel.offline = False
        v = ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, None, unverified_reason="x")
    assert v.tier == ipintel.LIKELY and v.prior == ipintel.TENANT_COMPUTE


@pytest.mark.parametrize("ptr", ["lga34s34-in-f14.1e100.net", "myshopify.com",
                                 "cdn-185-199-108-153.github.com",
                                 "a0b1.awsglobalaccelerator.com", "server-1-2.cloudfront.net",
                                 "a23-1-2-3.deploy.static.akamaitechnologies.com",
                                 "s3-website-us-east-1.amazonaws.com"])
def test_shared_ptr_is_shared_without_probing(intel, ptr):
    p = make_probe()
    with mock.patch.object(ipintel, "_ptr_lookup", return_value=ptr):
        intel.offline = False
        v = ipintel.classify("198.51.100.10", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.SHARED and "PTR" in v.reason
    assert p.calls["target"] == 0


def test_ec2_ptr_is_not_shared():
    assert not ipintel.ptr_is_shared("ec2-3-80-0-10.compute-1.amazonaws.com")
    assert not ipintel.ptr_is_shared("")


def test_akamai_asn_is_shared(intel):
    v = ipintel.classify("23.32.1.1", TARGET, intel, BASELINE, make_probe())
    assert v.tier == ipintel.SHARED and "Akamai" in v.reason


# === Negative controls / Layer 3 ============================================

@pytest.mark.parametrize("ip", sorted(PROBES))
def test_recorded_platform_fingerprints_are_shared(intel, ip):
    rec = PROBES[ip]
    assert ipintel.cert_platform(rec["nosni_cert"]) == rec["platform"]
    assert ipintel.response_platform(rec["bogus_host"]) != ""
    # Replayed against an IP no feed knows: the controls alone must catch it,
    # even though the target Host serves the real site with a valid cert.
    p = make_probe(target_cert=LE_TARGET, ctrl_http=rec["bogus_host"], nosni=rec["nosni_cert"])
    v = ipintel.classify("198.51.100.10", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.SHARED
    p = make_probe(target_cert=LE_TARGET, ctrl_http=rec["bogus_host"], nosni=NO_CERT)
    assert ipintel.classify("198.51.100.10", TARGET, intel, BASELINE, p).tier == ipintel.SHARED


def test_shopify_edge_serving_real_shop_is_shared_not_confirmed(intel):
    """Regression: an unlisted Shopify edge answers Host: shop.example.com with
    the real shop and a valid custom-domain cert, but presents *.myshopify.com
    without SNI. Content + SAN match must not confirm it."""
    shop = PROBES["23.227.38.65"]
    p = make_probe(hit=resp(body=SITE.format(n=7)),
                   target_cert={**LE_TARGET, "cn": "shop.example.com", "sans": ["shop.example.com"]},
                   ctrl_http=resp("404", "<title>Not found</title>"), nosni=shop["nosni_cert"])
    v = ipintel.classify("198.51.100.10", "shop.example.com", intel, BASELINE, p)
    assert v.tier == ipintel.SHARED
    assert "shopify" in v.reason


def test_generic_nginx_default_with_origin_ca_and_matching_body_is_confirmed(intel):
    p = make_probe(target_cert=ORIGIN_CA, ctrl_http=resp("200", NGINX_DEFAULT))
    v = ipintel.classify("198.51.100.10", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.CONFIRMED
    assert "Origin CA" in v.reason


def test_tenant_compute_ec2_with_san_and_matching_body_is_confirmed_and_scoped(intel):
    """False-negative guard: the target's own EC2 VM must not be lost."""
    p = make_probe(target_cert=LE_TARGET, ctrl_http=resp("404", NGINX_DEFAULT))
    with mock.patch.object(ipintel, "_ptr_lookup", return_value="ec2-3-80-0-10.compute-1.amazonaws.com"):
        intel.offline = False
        v = ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.CONFIRMED and v.prior == ipintel.TENANT_COMPUTE
    row = {"ip": "3.80.0.10", "sources": ["www.example.com"], **v.row()}
    assert ipintel.scan_targets([row]) == [row]
    s = scope.default(TARGET).with_hosts([o["ip"] for o in ipintel.scan_targets([row])])
    assert s.host_allowed("3.80.0.10")


def test_own_network_with_client_cert_required_is_likely(intel):
    # 198.51.100.0/24 is announced as "ACMECORP-AS Acme Corp" in the fixture.
    p = make_probe(hit=resp("000"), target_cert={**NO_CERT, "client_cert_required": True})
    v = ipintel.classify("198.51.100.10", "acmecorp.com", intel, BASELINE, p)
    assert v.prior == ipintel.OWN_NETWORK
    assert v.tier == ipintel.LIKELY and "client certificate" in v.reason


def test_client_cert_required_without_own_network_is_rejected(intel):
    p = make_probe(hit=resp("000"), target_cert={**NO_CERT, "client_cert_required": True})
    assert ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, p).tier == ipintel.REJECTED


def test_catch_all_without_tls_evidence_is_likely(intel):
    same = resp(body=SITE.format(n=3))
    p = make_probe(hit=same, ctrl_http=same)
    v = ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.LIKELY


def test_dissimilar_content_is_rejected(intel):
    p = make_probe(hit=resp(body=NGINX_DEFAULT), target_cert=ORIGIN_CA)
    v = ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.REJECTED


def test_error_status_is_rejected(intel):
    p = make_probe(hit=resp("502", SITE.format(n=1)))
    assert ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, p).tier == ipintel.REJECTED


def test_redirect_to_self_matching_baseline_redirect_is_accepted(intel):
    base = resp("301", "", {"location": "https://www.example.com/"})
    p = make_probe(hit=resp("301", "", {"location": "https://www.example.com/"}),
                   target_cert=ORIGIN_CA)
    assert ipintel.classify("3.80.0.10", TARGET, intel, base, p).tier == ipintel.CONFIRMED
    p = make_probe(hit=resp("302", "", {"location": "https://evil.test/"}), target_cert=ORIGIN_CA)
    assert ipintel.classify("3.80.0.10", TARGET, intel, base, p).tier == ipintel.REJECTED


def test_unknown_prior_with_only_san_evidence_is_capped(intel):
    same = resp(body=SITE.format(n=3))
    p = make_probe(hit=same, ctrl_http=same, target_cert=LE_TARGET)
    v = ipintel.classify("198.51.100.10", TARGET, intel, BASELINE, p)
    assert v.prior == ipintel.UNKNOWN
    assert v.tier == ipintel.LIKELY and "capped" in v.reason


def test_challenge_baseline_caps_at_likely(intel):
    challenge = resp("403", "<title>Just a moment...</title>", {"cf-mitigated": "challenge"})
    p = make_probe(target_cert=ORIGIN_CA)
    v = ipintel.classify("3.80.0.10", TARGET, intel, challenge, p)
    assert v.tier == ipintel.LIKELY and "challenge" in v.reason


def test_similarity_ignores_tokens_but_not_different_pages():
    assert ipintel.similar(SITE.format(n=1), SITE.format(n=99999))
    assert not ipintel.similar(SITE.format(n=1), NGINX_DEFAULT)
    assert not ipintel.similar("", "")


# === Fail-closed / cache behaviour ==========================================

def test_missing_azure_feed_caps_every_row_at_likely(tmp_path):
    intel = ipintel.IpIntel.load(build_cache(tmp_path / "c", skip=("azure",)), offline=True)
    assert intel.degraded and intel.missing == ["azure"]
    p = make_probe(target_cert=ORIGIN_CA)
    v = ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, p)
    assert v.tier == ipintel.LIKELY and "azure" in v.reason


def test_empty_cache_is_degraded_and_nothing_confirms(tmp_path):
    intel = ipintel.IpIntel.load(tmp_path / "empty", offline=True)
    assert intel.degraded
    # the built-in static list still works without any feed
    assert intel.range_class("76.76.21.21") == "SHARED:vercel:apex"
    v = ipintel.classify("3.80.0.10", TARGET, intel, BASELINE, make_probe(target_cert=ORIGIN_CA))
    assert v.tier == ipintel.LIKELY


def test_feed_older_than_30_days_counts_as_missing(tmp_path):
    root = build_cache(tmp_path / "c", age=31 * ipintel.DAY)
    intel = ipintel.IpIntel.load(root, offline=True)
    assert "aws" in intel.missing
    assert intel.range_class("3.80.0.10") == "TENANT_COMPUTE:aws:EC2"  # still used


def test_stale_cache_is_used_with_warning_when_refresh_raises(tmp_path):
    root = build_cache(tmp_path / "c", age=2 * ipintel.DAY)
    with mock.patch.object(ipintel, "_fetch", side_effect=OSError("network down")), \
         mock.patch.object(ipintel, "_fetch_spf", return_value=False), \
         mock.patch.object(utils, "warn") as warn:
        intel = ipintel.IpIntel.load(root)
    assert intel.range_class("3.80.0.10") == "TENANT_COMPUTE:aws:EC2"
    assert not intel.degraded
    assert any("aws" in c.args[0] and "cached copy" in c.args[0] for c in warn.call_args_list)


def test_truncated_refresh_is_rejected_in_favour_of_old_file(tmp_path):
    root = build_cache(tmp_path / "c", age=2 * ipintel.DAY)
    old = (root / "aws" / "raw").read_bytes()
    full = json.loads(old)
    full["prefixes"] = full["prefixes"][:2]
    full["ipv6_prefixes"] = []

    def fake_fetch(url, dest, proxy=None, headers=()):
        if "amazonaws" in url:
            Path(dest).write_text(json.dumps(full))
            return True
        return False

    with mock.patch.object(ipintel, "_fetch", side_effect=fake_fetch), \
         mock.patch.object(ipintel, "_fetch_spf", return_value=False), \
         mock.patch.object(utils, "warn") as warn:
        intel = ipintel.IpIntel.load(root)
    assert (root / "aws" / "raw").read_bytes() == old
    assert intel.range_class("3.5.140.2") == "SHARED:aws:S3"
    assert any("truncated" in c.args[0] for c in warn.call_args_list)


def test_successful_refresh_installs_new_copy_with_meta(tmp_path):
    root = tmp_path / "c"

    def fake_fetch(url, dest, proxy=None, headers=()):
        if "amazonaws" in url:
            shutil.copy(FIX / "aws.json", dest)
            return True
        return False

    with mock.patch.object(ipintel, "_fetch", side_effect=fake_fetch), \
         mock.patch.object(ipintel, "_fetch_spf", return_value=False), \
         mock.patch.object(utils, "warn"):
        intel = ipintel.IpIntel.load(root)
    meta = json.loads((root / "aws" / "meta.json").read_text())
    assert meta["prefix_count"] == 13 and meta["version"] == "1763251393"
    assert intel.range_class("75.2.1.1") == "SHARED:aws:GLOBALACCELERATOR"


def test_offline_makes_zero_network_calls(tmp_path):
    root = build_cache(tmp_path / "c", age=3 * ipintel.DAY)  # stale: would refresh online
    boom = mock.Mock(side_effect=AssertionError("network used"))
    with mock.patch.object(ipintel, "_fetch", boom), mock.patch.object(ipintel, "_dig_txt", boom), \
         mock.patch.object(ipintel, "_ptr_lookup", boom), \
         mock.patch.object(ipintel, "_rdap_fetch", boom), \
         mock.patch.object(ipintel, "_fetch_spf", boom):
        intel = ipintel.IpIntel.load(root, offline=True)
        for ip in ("3.80.0.10", "198.51.100.77", "203.0.113.5"):
            ipintel.classify(ip, TARGET, intel, None, None, unverified_reason="offline")
    boom.assert_not_called()


# === Integration: origin_hunt / origin_deep / cli scope gate ===============

def _hunt(tmp_path, resolve_map, prox=None, cache_skip=()):
    build_cache(Path(os.environ["BOUNTY_RUN_IPINTEL_DIR"]), skip=cache_skip)
    ipintel.configure(offline=True)
    verify = mock.Mock(side_effect=lambda t, ip: resp(body=SITE.format(n=5)))
    with mock.patch.object(stages, "_resolve_all", side_effect=lambda h: resolve_map.get(h, [])), \
         mock.patch.object(stages, "_resolve", return_value=""), \
         mock.patch.object(stages, "_canonical_name", side_effect=lambda h: h), \
         mock.patch.object(stages, "_cloudflare_ranges", return_value=list(CF_RANGES)), \
         mock.patch.object(stages, "_mx_hosts", return_value=[]), \
         mock.patch.object(stages, "_verify_origin", verify), \
         mock.patch.object(utils, "log"), mock.patch.object(utils, "warn"):
        rows = stages.origin_hunt("yoco.com", tmp_path, {"ip": "104.16.1.1"}, proxy=prox)
    return rows, verify


def test_origin_hunt_vercel_www_is_shared_never_probed_never_scoped(tmp_path):
    ctrl = mock.Mock()
    with mock.patch.object(ipintel, "control_probe", ctrl), \
         mock.patch.object(ipintel, "tls_cert", ctrl):
        rows, verify = _hunt(tmp_path, {"www.yoco.com": ["76.76.21.21"]})
    verify.assert_not_called()
    ctrl.assert_not_called()
    assert [(r["ip"], r["tier"]) for r in rows] == [("76.76.21.21", ipintel.SHARED)]
    assert ipintel.scan_targets(rows) == []
    text = (tmp_path / "origin_candidates.txt").read_text()
    assert text.startswith("# SHARED\t76.76.21.21\trange feed vercel:apex")


def test_origin_hunt_classifies_every_a_record(tmp_path):
    rows, _ = _hunt(tmp_path, {"www.yoco.com": ["76.76.21.21", "3.80.0.10"]})
    assert {r["ip"]: r["tier"] for r in rows}["76.76.21.21"] == ipintel.SHARED
    assert "3.80.0.10" in {r["ip"] for r in rows}


def test_origin_hunt_confirmed_origin_end_to_end(tmp_path):
    with mock.patch.object(ipintel, "tls_cert", return_value=ORIGIN_CA), \
         mock.patch.object(ipintel, "baseline_probe", return_value=BASELINE), \
         mock.patch.object(ipintel, "control_probe",
                           return_value={"http": resp("404", NGINX_DEFAULT), "nosni_cert": NO_CERT}):
        rows, verify = _hunt(tmp_path, {"direct.yoco.com": ["3.80.0.10"]})
    assert rows[0]["tier"] == ipintel.CONFIRMED and rows[0]["status"] == "200"
    assert verify.call_count == 1
    line = (tmp_path / "origin_candidates.txt").read_text().splitlines()[0]
    assert line.startswith("3.80.0.10\t200\tdirect.yoco.com\tCONFIRMED\t")


def test_origin_hunt_missing_azure_feed_holds_every_row_at_likely_or_below(tmp_path):
    with mock.patch.object(ipintel, "tls_cert", return_value=ORIGIN_CA), \
         mock.patch.object(ipintel, "baseline_probe", return_value=BASELINE), \
         mock.patch.object(ipintel, "control_probe",
                           return_value={"http": resp("404", NGINX_DEFAULT), "nosni_cert": NO_CERT}):
        rows, _ = _hunt(tmp_path, {"direct.yoco.com": ["3.80.0.10"], "api.yoco.com": ["129.213.1.1"]},
                        cache_skip=("azure",))
    assert rows and all(ipintel.TIER_RANK[r["tier"]] <= ipintel.TIER_RANK[ipintel.LIKELY]
                        for r in rows)


def test_proxy_run_layer1_still_rejects_vercel_and_never_probes_or_queries_cymru(tmp_path):
    prox = proxy.parse("http://h:8080")
    dig = mock.Mock(return_value=[])
    ctrl = mock.Mock()
    with mock.patch.object(ipintel, "_dig_txt", dig), \
         mock.patch.object(ipintel, "control_probe", ctrl), mock.patch.object(ipintel, "tls_cert", ctrl), \
         mock.patch.object(ipintel, "baseline_probe", ctrl):
        rows, verify = _hunt(tmp_path, {"www.yoco.com": ["76.76.21.21"],
                                        "direct.yoco.com": ["3.80.0.20"]}, prox=prox)
    verify.assert_not_called()
    ctrl.assert_not_called()
    dig.assert_not_called()
    by = {r["ip"]: r for r in rows}
    assert by["76.76.21.21"]["tier"] == ipintel.SHARED
    assert by["3.80.0.20"]["tier"] == ipintel.LIKELY
    assert by["3.80.0.20"]["status"] == stages.UNVERIFIED_PROXY
    assert ipintel.scan_targets(rows) == []


def test_origin_deep_uses_the_same_classifier(tmp_path):
    build_cache(Path(os.environ["BOUNTY_RUN_IPINTEL_DIR"]))
    ipintel.configure(offline=True)

    def fake_run(cmd, **kw):
        return json.dumps([{"name_value": "shop.example.com\napi.example.com"}]) if "crt.sh" in cmd else ""

    res = {"shop.example.com": ["23.227.38.65"], "api.example.com": ["3.80.0.10"]}
    with mock.patch.object(utils, "run", side_effect=fake_run), \
         mock.patch.object(stages, "_resolve_all", side_effect=lambda h: res.get(h, [])), \
         mock.patch.object(stages, "_canonical_name", side_effect=lambda h: h), \
         mock.patch.object(stages, "_cloudflare_ranges", return_value=list(CF_RANGES)), \
         mock.patch.object(stages, "_verify_origin", return_value=resp("000")), \
         mock.patch.object(utils, "log"), mock.patch.object(utils, "warn"):
        rows = origin_deep.origin_deep(TARGET, tmp_path, {})
    by = {r["ip"]: r["tier"] for r in rows}
    assert by == {"23.227.38.65": ipintel.SHARED, "3.80.0.10": ipintel.REJECTED}


ROWS = [
    {"ip": "203.0.113.1", "sources": ["a"], "status": "200", "tier": ipintel.CONFIRMED, "reason": "x"},
    {"ip": "203.0.113.2", "sources": ["b"], "status": "200", "tier": ipintel.LIKELY, "reason": "x"},
    {"ip": "203.0.113.3", "sources": ["c"], "status": "404", "tier": ipintel.REJECTED, "reason": "x"},
    {"ip": "76.76.21.21", "sources": ["d"], "status": "", "tier": ipintel.SHARED, "reason": "x"},
    {"ip": "203.0.113.5", "sources": ["e"], "status": "200"},   # untiered: never admitted
]


def _gate_run(tmp_path, hunt_rows, deep_rows=()):
    args = cli.build_parser().parse_args(
        [TARGET, "--nmap", "--skip", "subs,live,cf,panel,waf,dork,content,api,param,secret,"
                                     "headers,cors,tech"])
    st = cli.RunState(TARGET)
    st.cf = {"target": TARGET, "cloudflare": True, "evidence": []}
    scope.set_active(scope.default(TARGET))
    try:
        with mock.patch.object(stages, "origin_hunt", return_value=[dict(r) for r in hunt_rows]), \
             mock.patch.object(origin_deep, "origin_deep", return_value=[dict(r) for r in deep_rows]), \
             mock.patch.object(nmap_scan, "nmap_scan", return_value=[]) as nm, \
             mock.patch.object(stages, "vuln_scan", return_value=[]) as vs, \
             mock.patch.object(cli, "write_summary"), \
             mock.patch.object(cli.report, "write_findings_report"), \
             mock.patch.object(utils, "warn") as warn, mock.patch.object(utils, "log"):
            cli._pipeline(args, TARGET, tmp_path, set(args.skip.split(",")), st)
        s = scope.active()
    finally:
        scope.reset()
    return st, nm, vs, s, warn


def test_scope_gate_admits_only_confirmed_origins(tmp_path):
    st, nm, vs, s, warn = _gate_run(tmp_path, ROWS)
    assert len(st.origins) == len(ROWS)                      # all reported
    assert [o["ip"] for o in nm.call_args.args[3]] == ["203.0.113.1"]
    assert [o["ip"] for o in vs.call_args.kwargs["origins"]] == ["203.0.113.1"]
    assert s.host_allowed("203.0.113.1")
    for ip in ("203.0.113.2", "203.0.113.3", "76.76.21.21", "203.0.113.5"):
        assert not s.host_allowed(ip), ip
    held = " ".join(c.args[0] for c in warn.call_args_list if "manual review" in c.args[0])
    assert "203.0.113.2" in held and "76.76.21.21" not in held


def test_scope_gate_conflicting_grades_take_the_conservative_tier(tmp_path):
    hunt = [{"ip": "203.0.113.1", "sources": ["a"], "status": "200", "tier": ipintel.CONFIRMED}]
    deep = [{"ip": "203.0.113.1", "sources": ["b"], "status": "200", "tier": ipintel.LIKELY}]
    st, nm, vs, s, _ = _gate_run(tmp_path, hunt, deep)
    assert st.origins[0]["tier"] == ipintel.LIKELY and st.origins[0]["sources"] == ["a", "b"]
    assert nm.call_args.args[3] == [] and vs.call_args.kwargs["origins"] == []
    assert not s.host_allowed("203.0.113.1")


def test_cli_ipintel_flags_reach_the_classifier(tmp_path):
    args = cli.build_parser().parse_args([TARGET, "--ipintel-offline", "--refresh-ipintel"])
    assert args.ipintel_offline and args.refresh_ipintel
    with mock.patch.object(ipintel, "configure") as conf:
        st = cli.RunState(TARGET)
        all_stages = ",".join(cli.STAGE_IDS)
        cli._pipeline(cli.build_parser().parse_args([TARGET, "--ipintel-offline", "--skip", all_stages]),
                      TARGET, tmp_path, set(cli.STAGE_IDS), st)
    conf.assert_called_once_with(offline=True, refresh=False)


# === Probe primitives (real implementations, utils.run mocked) ==============

@pytest.mark.ipintel_real
def test_http_probe_pins_ip_and_reads_headers_and_body():
    def fake_run(cmd, **kw):
        hdr = re.search(r"-D (\S+)", cmd).group(1)
        body = re.search(r"-o (\S+)", cmd).group(1)
        Path(hdr).write_text("HTTP/2 404\r\nServer: Vercel\r\nX-Vercel-Error: DEPLOYMENT_NOT_FOUND\r\n\r\n")
        Path(body).write_text("DEPLOYMENT_NOT_FOUND")
        return "404|76.76.21.21"

    with mock.patch.object(utils, "run", side_effect=fake_run) as run:
        r = ipintel.http_probe("x.invalid", "76.76.21.21")
    cmd = run.call_args.args[0]
    assert "-k" in cmd and "--resolve x.invalid:443:76.76.21.21" in cmd
    assert r["status"] == "404" and r["headers"]["x-vercel-error"] == "DEPLOYMENT_NOT_FOUND"
    assert ipintel.response_platform(r) == "vercel"


@pytest.mark.ipintel_real
def test_tls_cert_reads_origin_ca_without_trust_and_flags_client_cert():
    x509 = ("subject=O = \"CloudFlare, Inc.\", OU = CloudFlare Origin CA, CN = CloudFlare Origin Certificate\n"
            "issuer=C = US, O = \"CloudFlare, Inc.\", OU = CloudFlare Origin SSL Certificate Authority, "
            "L = San Francisco, ST = California\n"
            "X509v3 Subject Alternative Name: \n    DNS:*.example.com, DNS:example.com\n")

    def fake_run(cmd, **kw):
        if cmd.startswith("openssl s_client"):
            assert "-servername example.com" in cmd
            Path(re.search(r"> (\S+) 2>&1", cmd).group(1)).write_text(
                "CONNECTED\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                "verify error:num=20:unable to get local issuer certificate\n")
            return ""
        return x509

    with mock.patch.object(utils, "run", side_effect=fake_run):
        c = ipintel.tls_cert("203.0.113.9", "example.com")
    assert ipintel.cert_is_origin_ca(c) and ipintel.san_covers(c, "example.com")
    assert not c["client_cert_required"]

    def aop_run(cmd, **kw):
        assert "-noservername" in cmd
        Path(re.search(r"> (\S+) 2>&1", cmd).group(1)).write_text(
            "CONNECTED\nSSL alert number 116\ntlsv13 alert certificate required\n")
        return ""

    with mock.patch.object(utils, "run", side_effect=aop_run):
        c = ipintel.tls_cert("203.0.113.9", None)
    assert c["client_cert_required"] and c["error"] == "client_cert_required"


@pytest.mark.ipintel_real
def test_dig_txt_joins_multi_string_records():
    with mock.patch.object(utils, "have", return_value=True), \
         mock.patch.object(utils, "run", return_value='"13335 | 23.227.38.0/23 " "| CA | arin | 2013-09-19"\n'):
        assert ipintel._dig_txt("x") == ["13335 | 23.227.38.0/23 | CA | arin | 2013-09-19"]


# === Drift detection (opt-in, live) =========================================

@pytest.mark.network
@pytest.mark.skipif(os.environ.get("BOUNTY_RUN_NETWORK_TESTS") != "1",
                    reason="live drift check; set BOUNTY_RUN_NETWORK_TESTS=1")
@pytest.mark.parametrize("ip", sorted(PROBES))
def test_live_platform_fingerprints_have_not_drifted(ip):
    ctrl = ipintel.control_probe(ip)
    assert ipintel.cert_platform(ctrl["nosni_cert"]) or ipintel.response_platform(ctrl["http"]), (
        f"{ip} ({PROBES[ip]['platform']}) no longer fingerprints as a shared platform")


@pytest.mark.ipintel_real
def test_resolve_all_returns_every_a_record():
    with mock.patch.object(stages.socket, "gethostbyname_ex",
                           return_value=("www.example.com", [], ["203.0.113.2", "203.0.113.1", "203.0.113.2"])):
        assert stages._resolve_all("www.example.com") == ["203.0.113.1", "203.0.113.2"]
    with mock.patch.object(stages.socket, "gethostbyname_ex", side_effect=OSError):
        assert stages._resolve_all("nope.example.com") == []
