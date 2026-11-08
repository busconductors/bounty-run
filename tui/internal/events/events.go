// Package events decodes the engine's events.jsonl (schema v1) and follows it.
package events

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrVersion is returned by Decode for events with an unsupported major v.
var ErrVersion = errors.New("unsupported event schema version")

// Event is the union of all v1 event types; unused fields stay zero.
type Event struct {
	V           int
	T           int64
	Type        string
	Target      string
	Stage       string
	Status      string
	Reason      string
	Level       string
	Msg         string
	Tool        string
	Stream      string
	Line        string
	Severity    string
	Template    string
	Host        string
	URL         string
	Summary     string // finding.summary (text)
	Report      string
	SummaryPath string // run_end.summary (path)
	Error       string
	Stages      []string
	Flags       map[string]any
	Counts      map[string]int
	Totals      map[string]int
	DurationMs  int64
	Done        int
	Total       int
}

type wire struct {
	V          int            `json:"v"`
	T          int64          `json:"t"`
	Type       string         `json:"type"`
	Target     string         `json:"target"`
	Stage      string         `json:"stage"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason"`
	Level      string         `json:"level"`
	Msg        string         `json:"msg"`
	Tool       string         `json:"tool"`
	Stream     string         `json:"stream"`
	Line       string         `json:"line"`
	Severity   string         `json:"severity"`
	Template   string         `json:"template"`
	Host       string         `json:"host"`
	URL        string         `json:"url"`
	Summary    string         `json:"summary"`
	Report     string         `json:"report"`
	Error      string         `json:"error"`
	Stages     []string       `json:"stages"`
	Flags      map[string]any `json:"flags"`
	Counts     map[string]int `json:"counts"`
	Totals     map[string]int `json:"totals"`
	DurationMs int64          `json:"duration_ms"`
	Done       int            `json:"done"`
	Total      int            `json:"total"`
}

// UnmarshalJSON routes the shared "summary" key by event type.
func (e *Event) UnmarshalJSON(b []byte) error {
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*e = Event{
		V: w.V, T: w.T, Type: w.Type, Target: w.Target, Stage: w.Stage,
		Status: w.Status, Reason: w.Reason, Level: w.Level, Msg: w.Msg,
		Tool: w.Tool, Stream: w.Stream, Line: w.Line, Severity: w.Severity,
		Template: w.Template, Host: w.Host, URL: w.URL, Report: w.Report,
		Error: w.Error, Stages: w.Stages, Flags: w.Flags, Counts: w.Counts,
		Totals: w.Totals, DurationMs: w.DurationMs, Done: w.Done, Total: w.Total,
	}
	if w.Type == "run_end" {
		e.SummaryPath = w.Summary
	} else {
		e.Summary = w.Summary
	}
	return nil
}

// Decode parses one JSON line. It returns ErrVersion when v != 1.
func Decode(line []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return Event{}, fmt.Errorf("decode event: %w", err)
	}
	if e.V != 1 {
		return Event{}, fmt.Errorf("%w: v=%d", ErrVersion, e.V)
	}
	return e, nil
}

// Msg carries one decoded event for a run (bubbletea message).
type Msg struct {
	RunDir string
	Ev     Event
}

// WarnMsg reports a malformed line that was skipped.
type WarnMsg struct{ RunDir, Text string }

// VersionMsg reports that a run's log has an incompatible schema version.
type VersionMsg struct{ RunDir string }
