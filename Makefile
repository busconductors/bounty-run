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
	$(PYTHON) -m PyInstaller --noconfirm --clean --onedir --name bounty-run \
		--distpath dist --workpath build/pyinstaller --specpath build/pyinstaller \
		--add-data "$(CURDIR)/assets:assets" \
		--add-data "$(CURDIR)/runner/vendor/shcheck.py:runner/vendor" \
		--hidden-import socks --hidden-import urllib3.contrib.socks \
		bounty_run.py
	dist/bounty-run/bounty-run --help > /dev/null

lint:
	$(PYTHON) -m ruff check .
	@unformatted="$$(gofmt -l tui)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	cd tui && go vet ./...

test:
	$(PYTHON) -m pytest -q
	cd tui && go test ./...
