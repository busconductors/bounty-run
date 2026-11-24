package findings

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fpA, fpB = "0123456789ab", "ba9876543210"

const twoFindings = `[
 {"severity":"high","template":"t-a","name":"A","url":"https://a.com/x","host":"a.com"},
 {"severity":"low","template":"t-b","name":"B","url":"https://a.com/y","host":"a.com","evidence":"e"}
]`

func newRun(t *testing.T) (*Service, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "a.com", "20250101-000000")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := New(func(d string) (string, error) { return d, nil })
	s.retries, s.delay = 5, time.Millisecond
	return s, dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFindingsWithoutIndex(t *testing.T) {
	s, dir := newRun(t)
	write(t, dir, "findings.json", twoFindings)
	res, err := s.GetFindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 || res.IndexAvailable || res.Pending {
		t.Fatalf("res = %+v", res)
	}
	for _, f := range res.Findings {
		if f.Fingerprint != "" || f.EvidencePath != "" {
			t.Errorf("finding %+v has an evidence link without an index", f)
		}
	}
	if res.Findings[0].Template != "t-a" || res.Findings[0].Severity != "high" {
		t.Errorf("first = %+v", res.Findings[0])
	}
}

func TestFindingsWithIndexLinksEvidence(t *testing.T) {
	s, dir := newRun(t)
	write(t, dir, "findings.json", twoFindings)
	write(t, dir, "findings.index.json", `["`+fpA+`", null]`)
	if err := os.MkdirAll(filepath.Join(dir, "evidence", fpA, "1"), 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := s.GetFindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IndexAvailable || res.Findings[0].Fingerprint != fpA || res.Findings[1].Fingerprint != "" {
		t.Fatalf("res = %+v", res)
	}
	if want := filepath.Join(dir, "evidence", fpA); res.Findings[0].EvidencePath != want {
		t.Errorf("EvidencePath = %q, want %q", res.Findings[0].EvidencePath, want)
	}
}

func TestFindingsIndexLengthMismatchIgnored(t *testing.T) {
	s, dir := newRun(t)
	write(t, dir, "findings.json", twoFindings)
	write(t, dir, "findings.index.json", `["`+fpA+`"]`)
	res, err := s.GetFindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.IndexAvailable || len(res.Findings) != 2 {
		t.Fatalf("res = %+v", res)
	}
	for _, f := range res.Findings {
		if f.Fingerprint != "" {
			t.Errorf("fingerprint %q kept from a mismatched index", f.Fingerprint)
		}
	}
}

func TestFindingsPartialFileRetries(t *testing.T) {
	s, dir := newRun(t)
	write(t, dir, "findings.json", `[{"severity":"hi`)
	go func() {
		time.Sleep(10 * time.Millisecond)
		os.WriteFile(filepath.Join(dir, "findings.json"), []byte(twoFindings), 0o600)
	}()
	s.retries, s.delay = 200, 2*time.Millisecond
	res, err := s.GetFindings(dir)
	if err != nil || res.Pending || len(res.Findings) != 2 {
		t.Fatalf("after the write completes: res = %+v, err = %v", res, err)
	}

	write(t, dir, "findings.json", `[{"severity":"hi`)
	s.retries = 3
	res, err = s.GetFindings(dir)
	if err != nil {
		t.Fatalf("a still-partial file must not be an error: %v", err)
	}
	if !res.Pending || len(res.Findings) != 0 {
		t.Fatalf("res = %+v, want pending", res)
	}
}

func TestFindingsMissingFile(t *testing.T) {
	s, dir := newRun(t)
	res, err := s.GetFindings(dir)
	if err != nil || !res.Missing || res.Pending {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestEvidencePathStaysInRun(t *testing.T) {
	s, dir := newRun(t)
	outside := t.TempDir()
	write(t, dir, "findings.json", twoFindings)
	write(t, dir, "findings.index.json", `["../../../etc","`+fpB+`"]`)
	// A symlinked evidence dir that leaves the run.
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "evidence", fpB)); err != nil {
		t.Fatal(err)
	}
	res, err := s.GetFindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.EvidencePath != "" {
			t.Errorf("EvidencePath %q escapes the run", f.EvidencePath)
		}
	}
}

func TestGetFindingsRejectsDirsOutsideRoot(t *testing.T) {
	s := New(func(string) (string, error) { return "", os.ErrPermission })
	if _, err := s.GetFindings("/etc"); err == nil {
		t.Fatal("expected an error for a dir the resolver rejects")
	}
}
