# Contributing to Bounty Runner

Thanks for your interest in improving Bounty Runner. Bug reports, fixes and
new stages are welcome.

## Authorized testing only

Bounty Runner is a security testing tool. Only run it against systems you own
or have explicit, written permission to test, such as targets in scope of a
bug bounty program. Do not include real target data, scan output or
third-party vulnerability details in issues, tests or pull requests. Use
`example.com` and similar reserved names in fixtures. To report a
vulnerability in Bounty Runner itself, follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

## Development setup

Requirements: Python 3.10+, and Go (version in `tui/go.mod`) to build the TUI.

```
git clone https://github.com/busconductors/bounty-run.git
cd bounty-run
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
make tui            # builds bin/bounty-tui
```

External recon tools are optional for development; the test suite does not
require them. See the README for the tool list.

## Running tests

```
python -m pytest         # Python engine tests
make tui                 # build the TUI
cd tui && go test ./...  # TUI tests
```

All three should pass before you open a pull request.

## Pull requests

- Keep each pull request focused on one change, and describe what and why.
- Add or update tests for any behavior change or bug fix.
- Update the README and CHANGELOG when you change user-visible behavior,
  flags or output files.
- Match the style of the surrounding code; do not mix refactors with fixes.
- Never include credentials, real scan output or target data.
- Make sure the Commit policy below is respected.

## Commit policy

COMMIT: source (runner/, tui/), tests, public docs (README, CHANGELOG, LICENSE, SECURITY, CONTRIBUTING), Makefile/requirements.txt/go.mod/go.sum, config TEMPLATES only.

NEVER COMMIT:
- specs/plans/brainstorm notes (docs/superpowers/, plans/, SPEC-*.md, .superpowers/)
- AI/process attribution (Co-Authored-By trailers, 'audited by ...' notes)
- credentials/keys/.env/secrets
- scan output (outputs/, results/, findings DBs)
- build artifacts (bin/, __pycache__/, *.pyc)
- local tool state (.claude/, .superpowers/)

## License

By contributing, you agree that your contributions are licensed under the
project's MIT license (see [LICENSE](LICENSE)).
