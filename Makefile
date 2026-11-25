.PHONY: tui banner engine lint test
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
