.PHONY: tui banner engine lint test install
PYTHON ?= python3

# The TUI embeds the startup banner (go:embed cannot reach outside the module),
# so keep its copy in sync with assets/ before every build.
banner:
	cp assets/startup_banner.txt tui/internal/ui/assets/startup_banner.txt

tui: banner
	cd tui && go build -o ../bin/bounty-tui ./cmd/bounty-tui

# Engine sidecar. Always --onedir: --onefile unpacks to a temp dir at startup.
engine:
	$(PYTHON) -m PyInstaller --noconfirm --clean --distpath dist --workpath build/pyinstaller \
		packaging/bounty-run.spec
	$(PYTHON) packaging/smoke_sidecar.py dist/bounty-run

lint:
	$(PYTHON) -m ruff check .
	@unformatted="$$(gofmt -l core tui)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	cd core && go vet ./...
	cd tui && go vet ./...

test:
	$(PYTHON) -m pytest -q
	cd core && go test ./...
	cd tui && go test ./...

# One-shot install: build the TUI, make sure `requests` is importable (no sudo;
# falls back to a repo-local .venv), and write ~/.local/bin/bounty-run.
# Idempotent: safe to re-run.
install: tui
	@set -e; \
	repo="$(CURDIR)"; \
	if python3 -c "import requests" >/dev/null 2>&1; then \
		echo "requests: already available for system python3"; \
		py=python3; \
	else \
		echo "requests: not found; using $$repo/.venv (alternative: sudo apt install python3-requests)"; \
		[ -x "$$repo/.venv/bin/python" ] || python3 -m venv "$$repo/.venv"; \
		"$$repo/.venv/bin/pip" install -q -r "$$repo/requirements.txt"; \
		py="$$repo/.venv/bin/python"; \
	fi; \
	mkdir -p "$$HOME/.local/bin"; \
	tmp="$$HOME/.local/bin/.bounty-run.tmp"; \
	printf '#!/bin/bash\nexec %s "%s/bounty_run.py" "$$@"\n' "$$py" "$$repo" > "$$tmp"; \
	chmod +x "$$tmp"; \
	mv -f "$$tmp" "$$HOME/.local/bin/bounty-run"; \
	echo ""; \
	echo "Installed: $$HOME/.local/bin/bounty-run (engine: $$py)"; \
	echo ""; \
	echo "Next steps:"; \
	echo "  1. Make sure BOTH of these are on your PATH (add to your shell rc):"; \
	echo "       export PATH=\"\$$PATH:$$HOME/.local/bin:$$(go env GOPATH)/bin\""; \
	echo "  2. Run: bounty-run"; \
	echo "  3. Press 's' for the Setup screen and install the tools it flags."
