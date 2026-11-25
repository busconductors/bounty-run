package engine

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseDoctorJSON(t *testing.T) {
	data, err := os.ReadFile("testdata/doctor.json")
	if err != nil {
		t.Fatal(err)
	}
	tools, err := parseDoctor(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "nuclei" || tools[0].Status != "ok" {
		t.Errorf("bad tool 0: %+v", tools[0])
	}
	if tools[0].InstallMethods[0].Method != "go" {
		t.Errorf("method = %q", tools[0].InstallMethods[0].Method)
	}
	if tools[1].Status != "missing" || !tools[1].Optional || tools[1].InstallMethods[0].Method != "manual" {
		t.Errorf("bad tool 1: %+v", tools[1])
	}
	var s SetupSummary
	if err := json.Unmarshal([]byte(`{"schema":2,"results":[{"name":"x","outcome":"installed","method":"go","detail":""}]}`), &s); err != nil || s.Results[0].Outcome != "installed" {
		t.Errorf("setup parse: %v %+v", err, s)
	}
}
