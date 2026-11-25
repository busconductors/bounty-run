package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// InstallMethod is one way the engine can install a tool.
type InstallMethod struct {
	Method  string `json:"method"`
	Package string `json:"package"`
}

// Tool is one entry of `introspect doctor`. Status is ok, missing,
// unknown_version or installed_needs_path.
type Tool struct {
	Name           string          `json:"name"`
	RequiredBy     []string        `json:"required_by"`
	Optional       bool            `json:"optional"`
	Status         string          `json:"status"`
	Path           string          `json:"path"` // resolved binary; for installed_needs_path, the off-PATH location
	InstallMethods []InstallMethod `json:"install_methods"`
	InstallHint    string          `json:"install_hint"`
}

// SetupResult is one tool's outcome from `setup --json`. Outcome is one of
// already_ok, installed, installed_needs_path, skipped, failed, manual.
type SetupResult struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Method  string `json:"method"`
	Detail  string `json:"detail"`
}

// SetupSummary is the `setup --json` payload.
type SetupSummary struct {
	Results []SetupResult `json:"results"`
}

func parseDoctor(data []byte) ([]Tool, error) {
	var d struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse doctor json: %w", err)
	}
	return d.Tools, nil
}

// Doctor runs `<bin> introspect doctor` and returns the tool report.
func Doctor(bin string) ([]Tool, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command(bin, "introspect", "doctor")
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("doctor: %w: %s", err, errb.String())
	}
	return parseDoctor(out.Bytes())
}

// Setup runs `<bin> setup --json <args...>`. The engine exits non-zero when an
// install failed but still prints the summary, so valid JSON wins over the
// exit status.
func Setup(bin string, args []string) (SetupSummary, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command(bin, append([]string{"setup", "--json"}, args...)...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	var s SetupSummary
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		if runErr != nil {
			return s, fmt.Errorf("setup: %w: %s", runErr, errb.String())
		}
		return s, fmt.Errorf("parse setup json: %w", err)
	}
	return s, nil
}
