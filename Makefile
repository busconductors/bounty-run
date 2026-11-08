.PHONY: tui banner
# The TUI embeds the startup banner (go:embed cannot reach outside the module),
# so keep its copy in sync with assets/ before every build.
banner:
	cp assets/startup_banner.txt tui/internal/ui/assets/startup_banner.txt

tui: banner
	cd tui && go build -o ../bin/bounty-tui ./cmd/bounty-tui
