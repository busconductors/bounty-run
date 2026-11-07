"""Vendored advanced injection scanners (SSTI / NoSQL / CRLF).

Vendored from SpyHunt ``modules/advanced_scanners.py`` (SSTIScanner,
NoSQLInjectionScanner, CRLFScanner) with these edits per SPEC-PHASE6:

  * ANSI-color import + ``__main__`` demo stripped (stdlib + requests only).
  * RCE + config-dump SSTI probes removed (subprocess import, FreeMarker's
    exec utility, ERB backtick eval, Smarty's PHP tag, and the config-dump
    probe) -- only arithmetic echo, non-executing fingerprint probes, and
    engine error-string detection remain.
  * NoSQL time-based sleep probe dropped and the dead js-injection entry
    pruned; operator injection + auth-bypass kept.

The ``verify=False`` on every request is retained deliberately (Cloudflare
Origin CA certs, matching origin_hunt's ``-k``).
"""

import re
import time
import logging
import requests
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


class SSTIScanner:
    """Server-Side Template Injection (SSTI) vulnerability scanner."""

    def __init__(self):
        """Initialize SSTI scanner."""
        self.payloads = {
            'jinja2': [
                ('math', '{{7*7}}', '49'),
            ],
            'twig': [
                ('math', '{{7*7}}', '49'),
                ('env', '{{_self.env}}', 'Twig'),
            ],
            'freemarker': [
                ('math', '${7*7}', '49'),
            ],
            'velocity': [
                ('math', '#set($x=7*7)$x', '49'),
            ],
            'erb': [
                ('math', '<%= 7*7 %>', '49'),
            ],
            'smarty': [
                ('math', '{7*7}', '49'),
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
    """NoSQL injection vulnerability scanner"""

    def __init__(self):
        """Initialize NoSQL injection scanner"""
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

        for db_type, payloads in self.payloads.items():
            for payload_type, payload in payloads:
                try:
                    # Test URL-encoded payload
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()

                    # Send request
                    start_time = time.time()
                    response = requests.get(test_url, timeout=timeout, verify=False)
                    elapsed = time.time() - start_time

                    # Check for time-based injection
                    if 'sleep' in payload_type and elapsed >= 5:
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'NoSQL Injection',
                            'severity': 'critical',
                            'db_type': db_type,
                            'payload_type': payload_type,
                            'payload': payload,
                            'evidence': f'Time-based blind injection (elapsed: {elapsed:.2f}s)'
                        })
                        logger.critical(f"NoSQL injection found: {test_url}")

                    # Check for bypass indicators
                    elif self._check_bypass(response, payload_type):
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'NoSQL Injection',
                            'severity': 'high',
                            'db_type': db_type,
                            'payload_type': payload_type,
                            'payload': payload,
                            'evidence': response.text[:500]
                        })
                        logger.warning(f"Possible NoSQL injection: {test_url}")

                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue

        return findings

    def _check_bypass(self, response: requests.Response, payload_type: str) -> bool:
        """Check if authentication/authorization was bypassed"""
        bypass_indicators = [
            'welcome', 'dashboard', 'logged in', 'profile',
            'success', 'admin', 'authenticated'
        ]

        if 'bypass' in payload_type:
            return any(indicator in response.text.lower()
                       for indicator in bypass_indicators)

        return False


class CRLFScanner:
    """CRLF Injection vulnerability scanner"""

    def __init__(self):
        """Initialize CRLF scanner"""
        self.payloads = [
            ('url_encoded_rn', '%0d%0aSet-Cookie:mycookie=myvalue'),
            ('url_encoded_location', '%0d%0aLocation:http://evil.com'),
            ('url_encoded_n', '%0aSet-Cookie:mycookie=myvalue'),
            ('url_encoded_r', '%0dSet-Cookie:mycookie=myvalue'),
            ('raw_rn', '\r\nSet-Cookie:mycookie=myvalue'),
            ('raw_n', '\nSet-Cookie:mycookie=myvalue'),
            ('http_smuggling', '%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK'),
            ('xss_combo', '%0d%0a%0d%0a<script>alert(1)</script>'),
        ]

    def scan(self, url: str, timeout: int = 10) -> List[Dict]:
        """
        Scan for CRLF injection vulnerabilities

        Args:
            url: Target URL
            timeout: Request timeout

        Returns:
            List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        for param in params:
            for payload_type, payload in self.payloads:
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(
                        query=urlencode(test_params, doseq=True, safe='%')
                    ).geturl()

                    # Send request
                    response = requests.get(
                        test_url,
                        allow_redirects=False,
                        timeout=timeout,
                        verify=False
                    )

                    # Check if payload reflected in headers
                    for header, value in response.headers.items():
                        if 'mycookie' in value.lower() or 'evil.com' in value.lower():
                            findings.append({
                                'url': test_url,
                                'param': param,
                                'type': 'CRLF Injection',
                                'severity': 'high',
                                'payload_type': payload_type,
                                'payload': payload,
                                'evidence': f'{header}: {value}'
                            })
                            logger.warning(f"CRLF injection found: {test_url}")
                            break

                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue

        return findings
