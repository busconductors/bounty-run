package ui

import (
	_ "embed"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// startupBanner is assets/startup_banner.txt (the Braille face, the "Bunty Run"
// wordmark and "by Strasser Lab"), synced into this package by `make banner`.
//
//go:embed assets/startup_banner.txt
var startupBanner string

// bannerCaption spells the wordmark out in plain text under the art.
const bannerCaption = "Bunty Run by Strasser Lab"

// bannerLines is the art without trailing blank lines; text is never altered.
func bannerLines() []string {
	return strings.Split(strings.TrimRight(startupBanner, "\n"), "\n")
}

// bannerWidth/bannerHeight are the art's display size in cells.
func bannerWidth() int  { return lipgloss.Width(strings.Join(bannerLines(), "\n")) }
func bannerHeight() int { return len(bannerLines()) + 2 } // + blank + caption

// bannerView renders the art in red, then the caption centred beneath it.
// Each art line is styled on its own and right-padded to the art's width, so
// the block centres as a unit and the Braille cells are emitted unchanged.
func bannerView() string {
	lines := bannerLines()
	w := bannerWidth()
	art := make([]string, 0, len(lines))
	for _, l := range lines {
		art = append(art, bannerStyle.Render(l)+strings.Repeat(" ", w-lipgloss.Width(l)))
	}
	return lipgloss.JoinVertical(lipgloss.Center, strings.Join(art, "\n"), "",
		accentStyle.Render(bannerCaption))
}

// splashDuration is how long the startup splash stays up without a key.
const splashDuration = 2 * time.Second

type splashDoneMsg struct{}

func splashTimer() tea.Cmd {
	return tea.Tick(splashDuration, func(time.Time) tea.Msg { return splashDoneMsg{} })
}

// splashView centres the banner (or just the caption on a small terminal).
func splashView(width, height int) string {
	body := bannerView()
	if width > 0 && height > 0 && (width < bannerWidth() || height < bannerHeight()+2) {
		body = accentStyle.Render(bannerCaption)
	}
	body = lipgloss.JoinVertical(lipgloss.Center, body, "", dimStyle.Render("press any key"))
	if width <= 0 || height <= 0 {
		return body
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, body)
}
