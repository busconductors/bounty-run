// Package doctor shapes the engine's tool report for the Doctor screen: one
// row per tool with its status, version, path, install guidance and the
// stages or modifiers that depend on it. The report itself (and its caching
// and single-flight) comes from the catalog.
package doctor

import (
	"slices"

	"bountyrun/desktop/internal/catalog"
)

// Row statuses.
const (
	StatusOK      = "ok"
	StatusMissing = "missing"
	StatusError   = "error"
)

// Row is one tool.
type Row struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Version  string   `json:"version"`
	Path     string   `json:"path"`
	Optional bool     `json:"optional"`
	Guidance string   `json:"guidance"`
	Affects  []string `json:"affects"`
}

// Report is the Doctor screen's data. Missing counts rows with status missing.
type Report struct {
	Rows    []Row `json:"rows"`
	Missing int   `json:"missing"`
}

// Source supplies the engine's tool report; *catalog.Catalog is one.
type Source interface {
	Doctor() (catalog.Doctor, error)
	RecheckDoctor() (catalog.Doctor, error)
}

// Service serves the Doctor screen.
type Service struct{ src Source }

// New returns a Service reading from src.
func New(src Source) *Service { return &Service{src: src} }

// Report returns the (cached) tool report.
func (s *Service) Report() (Report, error) { return shape(s.src.Doctor()) }

// Recheck re-runs the tool check and returns its report.
func (s *Service) Recheck() (Report, error) { return shape(s.src.RecheckDoctor()) }

func shape(d catalog.Doctor, err error) (Report, error) {
	if err != nil {
		return Report{}, err
	}
	rep := Report{Rows: make([]Row, 0, len(d.Tools))}
	for _, t := range d.Tools {
		r := Row{
			Name: t.Name, Version: t.Version, Path: t.Path, Optional: t.Optional,
			Status:   status(t.Status),
			Guidance: t.InstallHint,
			Affects:  append([]string{}, t.RequiredBy...),
		}
		// A modifier named after its tool (amass) is affected too.
		if slices.Contains(d.MissingByStage[t.Name], t.Name) && !slices.Contains(r.Affects, t.Name) {
			r.Affects = append(r.Affects, t.Name)
		}
		if r.Status == StatusMissing {
			rep.Missing++
			if r.Guidance == "" {
				r.Guidance = "Install " + t.Name + " and make sure it is on PATH."
			}
		}
		rep.Rows = append(rep.Rows, r)
	}
	return rep, nil
}

// status maps the engine's status; unknown_version still means installed.
func status(s string) string {
	switch s {
	case "ok", "unknown_version":
		return StatusOK
	case "missing":
		return StatusMissing
	}
	return StatusError
}
