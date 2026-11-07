"""Vendored advanced injection scanners (SSTI / NoSQL).

Vendored from SpyHunt ``modules/advanced_scanners.py`` (SSTIScanner,
NoSQLInjectionScanner) with these edits per SPEC-PHASE6 and SPEC-PHASE6.1:

  * ANSI-color import + ``__main__`` demo stripped (stdlib + requests only).
  * RCE + config-dump SSTI probes removed (subprocess import, FreeMarker's
    exec utility, ERB backtick eval, Smarty's PHP tag, and the config-dump
    probe) -- only arithmetic echo, non-executing fingerprint probes, and
    engine error-string detection remain.
  * NoSQL time-based sleep probe dropped; the grep-for-auth-bypass heuristic
    is replaced with a baseline-vs-injected response diff (SPEC-PHASE6.1
    item 4).
  * CRLFScanner removed entirely (no reliable non-destructive signal,
    SPEC-PHASE6.1 item 6).
  * SSTI arithmetic canary made unique: ``7777777*7777777`` ->
    ``60493827160493827`` (SPEC-PHASE6.1 item 3).

The ``verify=False`` on every request is retained deliberately (Cloudflare
Origin CA certs, matching origin_hunt's ``-k``).
"""

import logging
import requests
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


class SSTIScanner:
    """Server-Side Template Injection (SSTI) vulnerability scanner."""

    def __init__(self):
        """Initialize SSTI scanner."""
        self.payloads = {
            'jinja2': [
                ('math', '{{7777777*7777777}}', '60493827160493827'),
            ],
            'twig': [
                ('math', '{{7777777*7777777}}', '60493827160493827'),
                ('env', '{{_self.env}}', 'Twig'),
            ],
            'freemarker': [
                ('math', '${7777777*7777777}', '60493827160493827'),
            ],
            'velocity': [
                ('math', '#set($x=7777777*7777777)$x', '60493827160493827'),
            ],
            'erb': [
                ('math', '<%= 7777777*7777777 %>', '60493827160493827'),
            ],
            'smarty': [
                ('math', '{7777777*7777777}', '60493827160493827'),
            ]
        }

    def scan(self, url: str, param: str, timeout: int = 10) -> List[Dict]:
        """
        Scan for SSTI vulnerabilities

        Args:
            url: Target URL
            param: Parameter to test
            timeout: Request timeout

        Returns:
            List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        for template_engine, payloads in self.payloads.items():
            for test_type, payload, expected in payloads:
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()

                    # Send request
                    response = requests.get(test_url, timeout=timeout, verify=False)

                    # Check if payload executed
                    if expected in response.text and payload not in response.text:
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'SSTI',
                            'severity': 'critical',
                            'template_engine': template_engine,
                            'test_type': test_type,
                            'payload': payload,
                            'evidence': f'Payload executed: expected "{expected}" found in response'
                        })
                        logger.critical(f"SSTI vulnerability found: {test_url} ({template_engine})")

                    # Check for template errors
                    elif self._check_template_errors(response.text, template_engine):
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'SSTI',
                            'severity': 'high',
                            'template_engine': template_engine,
                            'test_type': test_type,
                            'payload': payload,
                            'evidence': 'Template engine error detected'
                        })
                        logger.warning(f"Possible SSTI: {test_url} ({template_engine})")

                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue

        return findings

    def _check_template_errors(self, response_text: str, engine: str) -> bool:
        """Check for template engine errors"""
        error_patterns = {
            'jinja2': ['jinja', 'TemplateSyntaxError', 'UndefinedError'],
            'twig': ['twig', 'Twig_Error', 'Syntax Error in template'],
            'freemarker': ['freemarker', 'FreeMarker', 'Template parsing error'],
            'velocity': ['velocity', 'VelocityException'],
            'erb': ['erb', 'SyntaxError', 'ruby'],
            'smarty': ['smarty', 'Syntax Error in template']
        }

        patterns = error_patterns.get(engine, [])
        return any(pattern.lower() in response_text.lower() for pattern in patterns)


class NoSQLInjectionScanner:
    """NoSQL injection vulnerability scanner."""

    # Absolute body-length delta (chars) treated as a meaningful difference when
    # the status code is unchanged.
    LENGTH_THRESHOLD = 50

    def __init__(self):
        """Initialize NoSQL injection scanner."""
        self.payloads = {
            'mongodb': [
                ('ne_bypass', '{"$ne": null}'),
                ('gt_bypass', '{"$gt": ""}'),
                ('regex_bypass', '{"$regex": ".*"}'),
                ('or_bypass', "' || '1'=='1"),
            ],
            'couchdb': [
                ('selector_bypass', '{"selector": {"_id": {"$gt": null}}}'),
            ]
        }

    def scan(self, url: str, param: str, timeout: int = 10) -> List[Dict]:
        """
        Scan for NoSQL injection vulnerabilities

        Args:
            url: Target URL
            param: Parameter to test
            timeout: Request timeout

        Returns:
            List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Baseline: a normal (non-operator) value for the target parameter.
        baseline_params = params.copy()
        baseline_params[param] = ['1']
        baseline_url = parsed_url._replace(
            query=urlencode(baseline_params, doseq=True)
        ).geturl()
        try:
            baseline = requests.get(baseline_url, timeout=timeout, verify=False)
        except requests.RequestException:
            return findings

        for db_type, payloads in self.payloads.items():
            for payload_type, payload in payloads:
                try:
                    # Build test URL with the operator-injection payload
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()

                    # Send request
                    response = requests.get(test_url, timeout=timeout, verify=False)

                    # Flag only on a meaningful baseline-vs-injected difference
                    if self._meaningful_diff(baseline, response):
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'NoSQL Injection',
                            'severity': 'medium',
                            'db_type': db_type,
                            'payload_type': payload_type,
                            'payload': payload,
                            'evidence': (
                                f'response differs from baseline '
                                f'(status {baseline.status_code}->{response.status_code}, '
                                f'len {len(baseline.text)}->{len(response.text)})'
                            ),
                        })
                        logger.warning(f"Possible NoSQL injection: {test_url}")

                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue

        return findings

    @staticmethod
    def _meaningful_diff(baseline: requests.Response, injected: requests.Response) -> bool:
        """True if the injected response meaningfully differs from the baseline.

        A status-code change is a strong signal; otherwise a body-length swing of
        at least ``LENGTH_THRESHOLD`` characters is treated as meaningful.
        """
        if baseline.status_code != injected.status_code:
            return True
        return abs(len(injected.text) - len(baseline.text)) >= NoSQLInjectionScanner.LENGTH_THRESHOLD
