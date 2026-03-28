package report

import (
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestWriteTextReportNoFindingsOmitsThresholdLine(t *testing.T) {
	report := model.Report{
		TargetPath:         ".",
		TargetPaths:        []string{".", "/tmp"},
		Profile:            model.ProfileDeveloper,
		FindingsBySeverity: map[string]int{},
		Findings:           nil,
		FailOn:             model.SeverityHigh,
		ThresholdExceeded:  true,
	}
	var buf strings.Builder
	WriteTextReport(&buf, report)
	out := buf.String()
	if !strings.Contains(out, "no findings") {
		t.Fatalf("expected no findings text in report")
	}
	if strings.Contains(out, "threshold exceeded") {
		t.Fatalf("threshold line should not be printed when no findings exist")
	}
}
