package ui

import "github.com/busconductors/bounty-run/core/textsafe"

// sanitize makes engine-supplied text safe to print; see textsafe.Sanitize.
func sanitize(s string) string { return textsafe.Sanitize(s) }

// oneLine sanitizes s for a single table cell; see textsafe.OneLine.
func oneLine(s string) string { return textsafe.OneLine(s) }
