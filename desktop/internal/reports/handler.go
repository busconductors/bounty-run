// Package reports serves a run's summary.html to the sandboxed report viewer
// and validates the report files the app may open externally. It is plain
// net/http: the Wails wiring lives in internal/bridge.
//
// Only files directly inside a run directory (root/<target>/<stamp>) are ever
// served, only by allowlisted name, and both the run directory and the final
// file are resolved through symlinks and checked to stay inside the root.
package reports

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Prefix is the URL path under which reports are served:
// /reports/<target>/<stamp>/summary.html (each segment percent-encoded).
const Prefix = "/reports/"

// HTMLReport is the one servable file. summary.html is self-contained (inline
// style and script, no linked assets), so nothing else needs serving.
const HTMLReport = "summary.html"

// MarkdownReports are the files that may be opened with the OS handler.
var MarkdownReports = []string{"FINDINGS.md", "SUMMARY.md"}

// CSP is sent with every report response. The report needs its inline script
// and style; everything else (network, forms, base) is denied. The sandbox
// directive gives the document an opaque origin even when loaded top-level.
// frame-ancestors is deliberately absent: 'self' may not match the Wails
// custom-scheme origin in WebKit and would blank the iframe; the iframe's
// sandbox attribute plus this directive already contain the report.
const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; sandbox allow-scripts"

// ErrNotFound covers every rejection, so callers cannot tell a missing file
// from a forbidden one.
var ErrNotFound = errors.New("report not found")

// SafeFile returns the real path of name inside runDir. name must be one of
// allowed. runDir must be a directory strictly inside root once symlinks are
// resolved, and the file must resolve to a regular file inside that directory.
func SafeFile(root, runDir, name string, allowed []string) (string, error) {
	ok := false
	for _, a := range allowed {
		ok = ok || a == name
	}
	if !ok {
		return "", ErrNotFound
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", ErrNotFound
	}
	realRun, err := filepath.EvalSymlinks(runDir)
	if err != nil || !within(realRoot, realRun) {
		return "", ErrNotFound
	}
	realFile, err := filepath.EvalSymlinks(filepath.Join(realRun, name))
	if err != nil || !within(realRun, realFile) || filepath.Dir(realFile) != realRun {
		return "", ErrNotFound
	}
	if fi, err := os.Stat(realFile); err != nil || !fi.Mode().IsRegular() {
		return "", ErrNotFound
	}
	return realFile, nil
}

// within reports whether p is strictly inside dir.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Handler serves reports from the runs under root. It answers GET and HEAD.
type Handler struct {
	root string
}

// New returns a Handler for runs under root.
func New(root string) *Handler { return &Handler{root: root} }

// segment decodes one escaped path segment, refusing anything that could
// change directory: empty, dot segments, separators, NUL.
func segment(escaped string) (string, bool) {
	s, err := url.PathUnescape(escaped)
	if err != nil || s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\\x00") || filepath.IsAbs(s) {
		return "", false
	}
	return s, true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path, ok := h.resolve(r.URL.EscapedPath())
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Content-Security-Policy", CSP)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.Copy(w, f)
	}
}

func (h *Handler) resolve(escaped string) (string, bool) {
	rest, ok := strings.CutPrefix(escaped, Prefix)
	if !ok {
		return "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return "", false
	}
	var seg [3]string
	for i, p := range parts {
		if seg[i], ok = segment(p); !ok {
			return "", false
		}
	}
	file, err := SafeFile(h.root, filepath.Join(h.root, seg[0], seg[1]), seg[2], []string{HTMLReport})
	return file, err == nil
}

// Mount returns a handler that sends /reports/ requests to reports and every
// other request to fallback.
func Mount(reports, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.EscapedPath(), Prefix) {
			reports.ServeHTTP(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}
