package engine

import "slices"

// Preset is a named stage selection. Stages are stage ids and sub-steps (the
// --skip tokens, plus opt-in stages of the same name); Flags are modifier flags
// that have no stage of their own (amass, nmap-full). Together they are the
// full list of enabled toggles.
type Preset struct {
	ID            string
	Stages, Flags []string
}

// Presets returns Quick, Standard and Deep. Each call returns fresh slices.
func Presets() []Preset {
	quick := []string{"subs", "panel", "live", "cf", "origin", "origin_deep", "waf", "dork", "secret", "headers", "cors", "tech"}
	standard := append(slices.Clone(quick), "nmap", "vuln", "content", "api")
	deep := append(slices.Clone(standard), "param", "tls", "nikto", "metis", "headi")
	return []Preset{
		{ID: "quick", Stages: quick},
		{ID: "standard", Stages: standard},
		{ID: "deep", Stages: deep, Flags: []string{"amass", "nmap-full"}},
	}
}
