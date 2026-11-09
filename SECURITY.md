# Security Policy

## Supported versions

Only the latest commit on `master` is supported. Please reproduce any issue against current `master` before reporting.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories: open the repository's **Security** tab and click **Report a vulnerability**. Do not open a public issue for security problems.

Please include:

- A description of the issue and its impact
- Steps to reproduce, or a minimal proof of concept
- Affected file(s), command(s), or stage(s) of Bounty Runner
- Your environment (OS, Python version, version or commit of Bounty Runner)
- Any suggested fix, if you have one

## Response expectations

We aim to acknowledge reports within about 7 days, and will keep you updated on triage and any fix. This is a best-effort project, so timelines for fixes may vary with severity.

## Scope

In scope: vulnerabilities in Bounty Runner's own code (for example, command or path injection, unsafe handling of scan output, SSRF-guard bypasses, or unintended disclosure of local data).

Out of scope: findings about third-party targets discovered while using the tool, and vulnerabilities in external tools it invokes (report those to their maintainers).

## Authorized use only

Bounty Runner is intended for security testing of systems you own or have explicit written permission to test, such as targets within a bug bounty program's scope. You are responsible for complying with applicable laws and program rules.
