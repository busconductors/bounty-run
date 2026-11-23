package events

import (
	"errors"
	"testing"
)

func TestDecodeAllTypes(t *testing.T) {
	cases := []struct {
		name string
		line string
		chk  func(t *testing.T, e Event)
	}{
		{"run_start", `{"v":1,"t":1000,"type":"run_start","target":"a.com","flags":{"amass":true,"timeout":30,"x":null},"stages":["live","nuclei"]}`, func(t *testing.T, e Event) {
			if e.Target != "a.com" || len(e.Stages) != 2 || e.Stages[1] != "nuclei" || e.Flags["amass"] != true || e.Flags["timeout"].(float64) != 30 {
				t.Errorf("bad: %+v", e)
			}
		}},
		{"stage_start", `{"v":1,"t":1,"type":"stage_start","stage":"live"}`, func(t *testing.T, e Event) {
			if e.Stage != "live" {
				t.Errorf("bad: %+v", e)
			}
		}},
		{"stage_end", `{"v":1,"t":1,"type":"stage_end","stage":"tls","status":"skipped","duration_ms":1234,"counts":{"hosts":3},"reason":"tool missing"}`, func(t *testing.T, e Event) {
			if e.Status != "skipped" || e.DurationMs != 1234 || e.Counts["hosts"] != 3 || e.Reason != "tool missing" {
				t.Errorf("bad: %+v", e)
			}
		}},
		{"progress", `{"v":1,"t":1,"type":"progress","stage":"ffuf","done":4,"total":9}`, func(t *testing.T, e Event) {
			if e.Done != 4 || e.Total != 9 || e.Stage != "ffuf" {
				t.Errorf("bad: %+v", e)
			}
		}},
		{"log", `{"v":1,"t":1,"type":"log","level":"warn","msg":"hi"}`, func(t *testing.T, e Event) {
			if e.Level != "warn" || e.Msg != "hi" {
				t.Errorf("bad: %+v", e)
			}
		}},
		{"output", `{"v":1,"t":1,"type":"output","stage":"nuclei","tool":"nuclei","stream":"stderr","line":"x"}`, func(t *testing.T, e Event) {
			if e.Tool != "nuclei" || e.Stream != "stderr" || e.Line != "x" || e.Stage != "nuclei" {
				t.Errorf("bad: %+v", e)
			}
		}},
		{"finding", `{"v":1,"t":1,"type":"finding","severity":"high","template":"cve-1","host":"h","url":"http://h/","summary":"text here"}`, func(t *testing.T, e Event) {
			if e.Severity != "high" || e.Template != "cve-1" || e.Host != "h" || e.URL != "http://h/" || e.Summary != "text here" || e.SummaryPath != "" {
				t.Errorf("bad: %+v", e)
			}
		}},
		{"run_end", `{"v":1,"t":1,"type":"run_end","status":"failed","totals":{"high":2},"report":"/r/FINDINGS.md","summary":"/r/SUMMARY.md","error":"boom"}`, func(t *testing.T, e Event) {
			if e.Status != "failed" || e.Totals["high"] != 2 || e.Report != "/r/FINDINGS.md" || e.SummaryPath != "/r/SUMMARY.md" || e.Summary != "" || e.Error != "boom" {
				t.Errorf("bad: %+v", e)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := Decode([]byte(c.line))
			if err != nil {
				t.Fatal(err)
			}
			if e.V != 1 || e.Type != c.name || e.T == 0 {
				t.Errorf("header wrong: %+v", e)
			}
			c.chk(t, e)
		})
	}
}

func TestDecodeVersion(t *testing.T) {
	_, err := Decode([]byte(`{"v":2,"t":1,"type":"log"}`))
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("want ErrVersion, got %v", err)
	}
}

func TestDecodeGarbage(t *testing.T) {
	if _, err := Decode([]byte("garbage")); err == nil || errors.Is(err, ErrVersion) {
		t.Fatalf("want decode error, got %v", err)
	}
}
