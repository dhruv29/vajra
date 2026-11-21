package demo

import (
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/report"
)

func TestRunIsConsistentAndRenders(t *testing.T) {
	run, err := Run("20261121-195440-0a1b2c3d", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}

	counted := 0
	for _, n := range run.Report.Summary {
		counted += n
	}
	if counted != len(run.Report.Findings) || len(run.Radii) != len(run.Report.Findings) {
		t.Fatalf("summary counts %d of %d findings; radii = %d", counted, len(run.Report.Findings), len(run.Radii))
	}
	if run.Report.Summary[finding.Confirmed] != 4 || run.Radii[0].FindingID != "demo-rce" || run.Radii[0].Score < 90 {
		t.Fatalf("summary = %v, top radius = %+v", run.Report.Summary, run.Radii[0])
	}
	if env, _ := run.Radius("demo-env"); env.Capability != "credential_exposure" {
		t.Fatalf("the exposed key was classified as %s", env.Capability)
	}
	if run.Reach == nil || run.Reach.DeniedTotal != 14 {
		t.Fatalf("reach = %+v", run.Reach)
	}
	if code, _ := run.Radius("demo-code-cmdi"); code.OriginID != "service:shop.example.test:443" || code.Score < 80 {
		t.Fatalf("the code finding is not anchored to its service: %+v", code)
	}
	for _, f := range run.Report.Findings {
		if f.Kind == finding.Static {
			continue
		}
		if !strings.Contains(f.Target, ".example.test") {
			t.Errorf("%s uses a host that is not reserved for examples: %s", f.ID, f.Target)
		}
	}
	html, err := report.HTML(run)
	if err != nil || !strings.Contains(string(html), "5 findings need attention") {
		t.Fatalf("HTML report: err = %v", err)
	}
}
