package sarif

import (
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

func FuzzParse(f *testing.F) {
	seeds := []string{
		codeQLReport,
		minimalReport,
		`{"version":"2.1.0","runs":[]}`,
		`{"runs":[{"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"%2e%2e/x"},"region":{"startLine":1}}}]}]}]}`,
		`{"runs":[{"originalUriBaseIds":{"A":{"uri":"x/","uriBaseId":"A"}},"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a","uriBaseId":"A"},"region":{"startLine":1}}}]}]}]}`,
		`{"runs":[{"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"C:\\a\\..\\..\\b"},"region":{"startLine":1}}}]}]}]}`,
		`{"runs":[{"tool":{"driver":{"rules":[{"id":"r","properties":{"security-severity":"1e400"}}]}},"results":[{"ruleIndex":0}]}]}`,
		`{"runs":[[]]}`,
		`{`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		findings, skipped, err := Parse(strings.NewReader(string(data)), Options{MaxResults: 50, Root: "/work/repo"})
		if err != nil {
			if !strings.HasPrefix(err.Error(), "sarif: ") || findings != nil {
				t.Fatalf("error %q, findings %d", err, len(findings))
			}
			return
		}
		if skipped < 0 || len(findings) > 50 {
			t.Fatalf("skipped %d, findings %d", skipped, len(findings))
		}
		seen := map[string]bool{}
		for _, fd := range findings {
			if fd.Location == nil || !finding.SafeRelPath(fd.Location.File) || fd.Location.Line < 1 || fd.Location.EndLine < fd.Location.Line {
				t.Fatalf("unsafe or unusable location %+v", fd.Location)
			}
			if !IsSource(fd.Source) || fd.RuleID == "" || seen[fd.ID] || fd.Kind != finding.Static {
				t.Fatalf("bad finding %+v", fd)
			}
			seen[fd.ID] = true
			if len(fd.RuleID) > maxRuleIDBytes || len(fd.Description) > maxMessageBytes || len(fd.Title) > maxTitleBytes {
				t.Fatalf("field not capped: %d %d %d", len(fd.RuleID), len(fd.Description), len(fd.Title))
			}
		}
	})
}
