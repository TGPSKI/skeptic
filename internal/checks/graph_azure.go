package checks

import (
	"encoding/json"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

const (
	azureBuiltinOwnerGUID       = "8e3af657-a8ff-443c-be75-558c510ff39d"
	azureBuiltinContributorGUID = "b24988ac-6180-42a0-ab88-20f7382dd24f"
)

// CheckAzureRoleAssignment detects high-privilege Azure role assignments in JSON policy exports.
func CheckAzureRoleAssignment(path, content string, redact bool) []model.Finding {
	if !strings.Contains(content, "roleDefinitionId") && !strings.Contains(content, "roleDefinitionName") {
		return nil
	}
	var root map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(content)), &root) != nil {
		return nil
	}
	idVal, nameVal := walkAzureRoleDefinitionStrings(root)
	sev, match := classifyAzurePrivilegedRole(idVal, nameVal)
	if match == "" {
		return nil
	}
	return []model.Finding{{
		RuleID:          "GRAPH-006",
		ConfidenceClass: model.ConfidenceDefinitive,
		Title:           "Azure role assignment grants Owner or Contributor",
		Description:     "Role assignment grants subscription or resource-group level Owner or Contributor, enabling broad control-plane changes.",
		Category:        "identity-graph",
		Mitre:           "T1078.004",
		Severity:        sev,
		File:            path,
		Match:           security.SanitizeMatch(match, redact),
	}}
}

func walkAzureRoleDefinitionStrings(v any) (roleDefinitionID, roleDefinitionName string) {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["roleDefinitionId"].(string); ok && s != "" {
			roleDefinitionID = s
		}
		if s, ok := t["roleDefinitionName"].(string); ok && s != "" {
			roleDefinitionName = s
		}
		if p, ok := t["properties"].(map[string]any); ok {
			ci, cn := walkAzureRoleDefinitionStrings(p)
			if ci != "" {
				roleDefinitionID = ci
			}
			if cn != "" {
				roleDefinitionName = cn
			}
		}
		for _, child := range t {
			ci, cn := walkAzureRoleDefinitionStrings(child)
			if ci != "" {
				roleDefinitionID = ci
			}
			if cn != "" {
				roleDefinitionName = cn
			}
		}
	case []any:
		for _, el := range t {
			ci, cn := walkAzureRoleDefinitionStrings(el)
			if ci != "" {
				roleDefinitionID = ci
			}
			if cn != "" {
				roleDefinitionName = cn
			}
		}
	}
	return roleDefinitionID, roleDefinitionName
}

func classifyAzurePrivilegedRole(id, name string) (sev model.Severity, match string) {
	lid := strings.ToLower(id)
	if strings.Contains(lid, strings.ToLower(azureBuiltinOwnerGUID)) {
		return model.SeverityCritical, "roleDefinitionId=" + id
	}
	if strings.Contains(lid, strings.ToLower(azureBuiltinContributorGUID)) {
		return model.SeverityHigh, "roleDefinitionId=" + id
	}
	n := strings.TrimSpace(name)
	if n == "" {
		return "", ""
	}
	ln := strings.ToLower(n)
	if strings.Contains(ln, "owner") {
		return model.SeverityCritical, "roleDefinitionName=" + name
	}
	if strings.Contains(ln, "contributor") {
		return model.SeverityHigh, "roleDefinitionName=" + name
	}
	return "", ""
}
