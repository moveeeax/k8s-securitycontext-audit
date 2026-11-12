package audit

import (
	"encoding/json"
	"io"
)

// Minimal SARIF 2.1.0 model, enough for code-scanning ingestion.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifText          `json:"shortDescription"`
	Properties       sarifRuleProps     `json:"properties"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	// Suppressions is set only for suppressed findings (SARIF 2.1.0 §3.27.23).
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifSuppression struct {
	// Kind is "inSource" (manifest annotation) or "external" (ignore file).
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps our severity to a SARIF level.
func sarifLevel(s Severity) string {
	switch s {
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF renders the report as SARIF 2.1.0.
func (r *Report) WriteSARIF(w io.Writer, version string) error {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := ruleSet[f.Rule]; !ok {
			ruleSet[f.Rule] = sarifRule{
				ID:               f.Rule,
				Name:             f.Rule,
				ShortDescription: sarifText{Text: ruleDescriptions[f.Rule]},
				Properties:       sarifRuleProps{Tags: []string{"security", "kubernetes"}},
				DefaultConfig:    sarifDefaultConfig{Level: sarifLevel(f.Severity)},
			}
		}
		res := sarifResult{
			RuleID:  f.Rule,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: resourceRef(f) + " / " + containerRef(f) + ": " + f.Message},
		}
		if f.Suppressed && f.Suppression != nil {
			kind := "external"
			if f.Suppression.Source == SourceAnnotation {
				kind = "inSource"
			}
			res.Suppressions = []sarifSuppression{{
				Kind:          kind,
				Status:        "accepted",
				Justification: f.Suppression.Reason,
			}}
		}
		if f.File != "" {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}},
			}}
		}
		results = append(results, res)
	}
	rules := make([]sarifRule, 0, len(ruleSet))
	for _, id := range ruleOrder {
		if rule, ok := ruleSet[id]; ok {
			rules = append(rules, rule)
		}
	}
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "k8s-securitycontext-audit",
				InformationURI: "https://github.com/moveeeax/k8s-securitycontext-audit",
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
