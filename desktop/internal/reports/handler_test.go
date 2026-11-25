package reports

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (root string, h http.Handler) {
	t.Helper()
	root = t.TempDir()
	run := filepath.Join(root, "ex.com", "20250101-000000")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	hostile, err := os.ReadFile(filepath.Join("testdata", "hostile.html"))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"summary.html": string(hostile), "findings.json": "[]", "FINDINGS.md": "# f"} {
		if err := os.WriteFile(filepath.Join(run, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, New(root)
}

func get(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "http://x/", nil)
	req.URL.Path, req.URL.RawPath = "", ""
	u := httptest.NewRequest(method, target, nil)
	req.URL = u.URL
	h.ServeHTTP(rec, req)
	return rec
}

const good = "/reports/ex.com/20250101-000000/summary.html"

func TestServesSummaryWithHostileFixtureUnderCSP(t *testing.T) {
	_, h := fixture(t)
	rec := get(h, "GET", good)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "window.parent.wails") {
		t.Fatalf("code %d body %q", rec.Code, rec.Body.String())
	}
}

func TestCSPHeaderPresent(t *testing.T) {
	_, h := fixture(t)
	rec := get(h, "GET", good)
	hd := rec.Header()
	csp := hd.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "form-action 'none'", "base-uri 'none'", "sandbox allow-scripts"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "frame-ancestors") {
		t.Errorf("CSP %q: frame-ancestors can blank the iframe under the Wails scheme", csp)
	}
	if strings.Contains(csp, "connect-src") || strings.Contains(csp, "*") {
		t.Errorf("CSP %q must not open connect-src or wildcards", csp)
	}
	if hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Cache-Control") != "no-store" || hd.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("headers %v", hd)
	}
	if head := get(h, "HEAD", good); head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("HEAD: %d %q", head.Code, head.Body.String())
	}
}

func TestRejectsTraversal(t *testing.T) {
	_, h := fixture(t)
	for _, p := range []string{
		"/reports/ex.com/20250101-000000/../../secret.txt",
		"/reports/ex.com/../summary.html",
		"/reports/../ex.com/20250101-000000/summary.html",
		"/reports/ex.com/20250101-000000/%2e%2e/summary.html",
		"/reports/ex.com/%2e%2e/%2e%2e/secret.txt",
		"/reports/ex.com%2f20250101-000000/summary.html",
		"/reports/ex.com/20250101-000000%2fsummary.html",
		"/reports/ex.com/20250101-000000/..%2f..%2fsecret.txt",
		"/reports/ex.com/20250101-000000/%2Fetc%2Fpasswd",
		"/reports/ex.com/20250101-000000/..%5csecret.txt",
		"/reports//ex.com/20250101-000000/summary.html",
		"/reports/ex.com/20250101-000000/summary.html/",
		"/reports/ex.com/20250101-000000/",
		"/reports/ex.com/",
		"/reports/",
	} {
		if rec := get(h, "GET", p); rec.Code != 404 {
			t.Errorf("%s: code %d, want 404", p, rec.Code)
		}
	}
}

func TestRejectsSymlinkEscape(t *testing.T) {
	root, h := fixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.html"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(root, "ex.com", "20250101-000000")
	// summary.html itself a symlink out of the run dir
	_ = os.Remove(filepath.Join(run, "summary.html"))
	if err := os.Symlink(filepath.Join(outside, "x.html"), filepath.Join(run, "summary.html")); err != nil {
		t.Fatal(err)
	}
	if rec := get(h, "GET", good); rec.Code != 404 {
		t.Errorf("file symlink: code %d", rec.Code)
	}
	// the run dir itself a symlink out of the root
	if err := os.Symlink(outside, filepath.Join(root, "ex.com", "20250102-000000")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "summary.html"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := get(h, "GET", "/reports/ex.com/20250102-000000/summary.html"); rec.Code != 404 {
		t.Errorf("dir symlink: code %d", rec.Code)
	}
}

func TestOnlyAllowlistedFiles(t *testing.T) {
	_, h := fixture(t)
	for _, name := range []string{"findings.json", "FINDINGS.md", "run.json", "missing.html", "Summary.html"} {
		if rec := get(h, "GET", "/reports/ex.com/20250101-000000/"+name); rec.Code != 404 {
			t.Errorf("%s: code %d, want 404", name, rec.Code)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if rec := get(h, m, good); rec.Code != 405 {
			t.Errorf("%s: code %d, want 405", m, rec.Code)
		}
	}
}

func TestSafeFileMarkdownAllowlist(t *testing.T) {
	root, _ := fixture(t)
	run := filepath.Join(root, "ex.com", "20250101-000000")
	if _, err := SafeFile(root, run, "FINDINGS.md", MarkdownReports); err != nil {
		t.Errorf("FINDINGS.md: %v", err)
	}
	for _, name := range []string{"findings.json", "../secret.txt", "summary.html"} {
		if _, err := SafeFile(root, run, name, MarkdownReports); err == nil {
			t.Errorf("%s allowed", name)
		}
	}
	if _, err := SafeFile(root, t.TempDir(), "FINDINGS.md", MarkdownReports); err == nil {
		t.Error("run dir outside root allowed")
	}
}

func TestMountRoutesPrefix(t *testing.T) {
	_, h := fixture(t)
	fb := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("assets")) })
	m := Mount(h, fb)
	if rec := get(m, "GET", "/index.html"); rec.Body.String() != "assets" {
		t.Error("fallback not used")
	}
	if rec := get(m, "GET", good); rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("report not routed")
	}
}

func TestSafeFileAllowsPDF(t *testing.T) {
	root, _ := fixture(t)
	run := filepath.Join(root, "ex.com", "20250101-000000")
	if err := os.WriteFile(filepath.Join(run, PDFReport), []byte("%PDF-1.4"), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := []string{PDFReport}
	p, err := SafeFile(root, run, PDFReport, allowed)
	if err != nil || filepath.Base(p) != "report.pdf" {
		t.Fatalf("path %q err %v", p, err)
	}
	for _, name := range []string{"../report.pdf", "../../secret.txt", "/etc/passwd"} {
		if _, err := SafeFile(root, run, name, allowed); err == nil {
			t.Errorf("%s resolved", name)
		}
	}
}
