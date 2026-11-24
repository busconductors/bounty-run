// Package findings reads a finished (or running) run's findings.json, and the
// findings.index.json of fingerprints parallel to it, for the Findings view.
//
// Both files are produced by the engine and may be mid-write when read; the
// service retries a bounded number of times and then reports the result as
// pending rather than as an error. Every string is engine output and is
// sanitized for display.
package findings

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bountyrun/core/textsafe"
)

const (
	defaultRetries = 20
	defaultDelay   = 50 * time.Millisecond
	maxFileBytes   = 64 << 20
	maxFieldBytes  = 4096
)

// fingerprintRE is the engine's fingerprint shape: 12 lowercase hex chars.
var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{12}$`)

// Finding is one row of findings.json. Fingerprint and EvidencePath are set
// only when the run has a matching findings.index.json.
type Finding struct {
	Severity     string `json:"severity"`
	Template     string `json:"template"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	Host         string `json:"host"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	EvidencePath string `json:"evidencePath,omitempty"`
}

// FindingsResult is what GetFindings returns. Pending means findings.json is
// not readable yet (partly written): the caller should ask again. Missing
// means the run has no findings.json. IndexAvailable is false for runs from
// before findings.index.json existed ("evidence link unavailable").
type FindingsResult struct {
	Findings       []Finding `json:"findings"`
	IndexAvailable bool      `json:"indexAvailable"`
	Pending        bool      `json:"pending"`
	Missing        bool      `json:"missing"`
}

// Service reads findings for runs under the outputs root.
type Service struct {
	resolve func(dir string) (string, error)
	retries int
	delay   time.Duration
}

// New returns a Service. resolve validates a run directory and returns it
// cleaned (runs.Service.RunDir), so only runs under the outputs root are read.
func New(resolve func(dir string) (string, error)) *Service {
	return &Service{resolve: resolve, retries: defaultRetries, delay: defaultDelay}
}

// GetFindings returns the findings of the run in dir.
func (s *Service) GetFindings(dir string) (FindingsResult, error) {
	dir, err := s.resolve(dir)
	if err != nil {
		return FindingsResult{}, err
	}
	var raw []map[string]any
	for i := 0; ; i++ {
		raw, err = readJSON[[]map[string]any](filepath.Join(dir, "findings.json"))
		if err == nil {
			break
		}
		if errors.Is(err, fs.ErrNotExist) {
			return FindingsResult{Findings: []Finding{}, Missing: true}, nil
		}
		var typ *json.UnmarshalTypeError
		if errors.As(err, &typ) {
			return FindingsResult{}, errors.New("findings.json has an unexpected format")
		}
		// Only a partly written file is worth waiting for; anything else
		// (permissions, I/O) will not fix itself.
		var syn *json.SyntaxError
		if !errors.As(err, &syn) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return FindingsResult{}, err
		}
		if i >= s.retries {
			return FindingsResult{Findings: []Finding{}, Pending: true}, nil
		}
		time.Sleep(s.delay)
	}
	res := FindingsResult{Findings: make([]Finding, len(raw))}
	for i, m := range raw {
		res.Findings[i] = Finding{
			Severity: field(m, "severity"), Template: field(m, "template"), Name: field(m, "name"),
			URL: field(m, "url"), Host: field(m, "host"),
		}
	}
	// The index is parallel to findings by position; a different length means
	// it belongs to some other write, so it is ignored.
	index, err := readJSON[[]*string](filepath.Join(dir, "findings.index.json"))
	if err != nil || len(index) != len(raw) {
		return res, nil
	}
	res.IndexAvailable = true
	for i, fp := range index {
		if fp == nil || !fingerprintRE.MatchString(*fp) {
			continue
		}
		res.Findings[i].Fingerprint = *fp
		res.Findings[i].EvidencePath = evidenceDir(dir, *fp)
	}
	return res, nil
}

// evidenceDir returns dir/evidence/<fp> when it exists and, after symlink
// resolution, lies inside dir; otherwise "".
func evidenceDir(dir, fp string) string {
	p := filepath.Clean(filepath.Join(dir, "evidence", fp))
	realRun, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return ""
	}
	realP, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	rel, err := filepath.Rel(realRun, realP)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return ""
	}
	return p
}

func readJSON[T any](path string) (T, error) {
	var v T
	f, err := os.Open(path)
	if err != nil {
		return v, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes))
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(b, &v)
	return v, err
}

func field(m map[string]any, key string) string {
	s, _ := m[key].(string)
	if len(s) > maxFieldBytes {
		s = s[:maxFieldBytes]
	}
	return textsafe.Sanitize(s)
}
