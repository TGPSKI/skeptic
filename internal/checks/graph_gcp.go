package checks

import (
	"encoding/json"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

type gcpIAMBindingDoc struct {
	Bindings []struct {
		Role    string   `json:"role"`
		Members []string `json:"members"`
	} `json:"bindings"`
}

// CheckGCPIAMBinding detects world-readable high-privilege GCP IAM bindings.
func CheckGCPIAMBinding(path, content string, redact bool) []model.Finding {
	if !strings.Contains(content, `"bindings"`) {
		return nil
	}
	var doc gcpIAMBindingDoc
	if json.Unmarshal([]byte(strings.TrimSpace(content)), &doc) != nil {
		return nil
	}
	if len(doc.Bindings) == 0 {
		return nil
	}
	var findings []model.Finding
	for _, b := range doc.Bindings {
		role := strings.TrimSpace(b.Role)
		if role != "roles/owner" && role != "roles/editor" {
			continue
		}
		for _, m := range b.Members {
			mm := strings.TrimSpace(m)
			if mm == "allUsers" || mm == "allAuthenticatedUsers" {
				match := role + " " + mm
				findings = append(findings, model.Finding{
					RuleID:          "GRAPH-007",
					ConfidenceClass: model.ConfidenceDefinitive,
					Title:           "GCP IAM binding exposes Owner or Editor to all users",
					Description:     "IAM binding grants roles/owner or roles/editor to allUsers or allAuthenticatedUsers.",
					Category:        "identity-graph",
					Mitre:           "T1078.004",
					Severity:        model.SeverityCritical,
					File:            path,
					Match:           security.SanitizeMatch(match, redact),
				})
				break
			}
		}
	}
	return findings
}
