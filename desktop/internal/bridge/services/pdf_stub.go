//go:build !(linux && cgo && !gtk3 && !android && !server && !purego)

package services

import "errors"

// webkitRenderPDF is unavailable outside the Linux WebKitGTK build (the only
// backend the app ships with). It exists so the package builds everywhere;
// ExportPDF then reports PDF export is unsupported rather than failing to link.
func webkitRenderPDF(htmlPath, pdfPath, theme string) error {
	return errors.New("PDF export requires the Linux WebKitGTK build")
}
