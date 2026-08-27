package scan

import (
	"github.com/TGPSKI/skeptic/internal/model"
)

var severityScoreWeight = map[model.Severity]float64{
	model.SeverityCritical: 25,
	model.SeverityHigh:     10,
	model.SeverityMedium:   4,
	model.SeverityLow:      1,
	model.SeverityInfo:     0,
}

// ComputeRiskScore calculates a 0–100 aggregate risk score with diminishing
// returns per severity bucket. Each additional finding of the same severity
// contributes less than the previous one.
func ComputeRiskScore(findings []model.Finding) int {
	counts := make(map[model.Severity]int)
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		counts[f.Severity]++
	}

	var total float64
	for sev, count := range counts {
		w := severityScoreWeight[sev]
		if w == 0 {
			continue
		}
		for i := 0; i < count; i++ {
			total += w / (1.0 + 0.1*float64(i))
		}
	}

	score := int(total)
	if score > 100 {
		score = 100
	}
	return score
}
