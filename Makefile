.PHONY: tui
tui:
	cd tui && go build -o ../bin/bounty-tui ./cmd/bounty-tui
