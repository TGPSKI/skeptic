package rules

import (
	"regexp"

	"github.com/TGPSKI/skeptic/internal/model"
)

// Rule is a shorthand alias for model.Rule to avoid qualifying 200+ struct literals.
type Rule = model.Rule

// Shorthand aliases for model severity, target, and confidence constants used in rule definitions.
const (
	SeverityInfo     = model.SeverityInfo
	SeverityLow      = model.SeverityLow
	SeverityMedium   = model.SeverityMedium
	SeverityHigh     = model.SeverityHigh
	SeverityCritical = model.SeverityCritical
	TargetContent    = model.TargetContent
	TargetPath       = model.TargetPath

	ConfidenceDefinitive = model.ConfidenceDefinitive
	ConfidenceHeuristic  = model.ConfidenceHeuristic
	ConfidenceCorrelated = model.ConfidenceCorrelated
)

// DefaultRules returns the full built-in detector library with precompiled regex patterns.
func DefaultRules() []Rule {
	var rules []Rule

	// Group 1: behavior and payload construction signals.
	rules = append(rules, behavioralSignalsRules()...)

	// Group 3: agentic ecosystem and trust-laundering surfaces.
	rules = append(rules, agenticSurfacesRules()...)
	rules = append(rules, nonCodeSurfacesRules()...)

	// Group 4: identity and credential exposure in infra/IaC artifacts.
	rules = append(rules, infrastructureCredentialExposureRules()...)
	rules = append(rules, machineIdentityPolicyRules()...)

	// Group 5: broad ATT&CK tactic coverage heuristics.
	rules = append(rules, attackTacticsRules()...)

	for i := range rules {
		rules[i].RE = regexp.MustCompile(rules[i].Pattern)
	}
	ApplyLiteralHints(rules)

	return rules
}
