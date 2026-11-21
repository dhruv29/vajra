package verify

import (
	"context"

	"github.com/dhruv29/vajra/internal/finding"
)

// CodeEvidenceStage requires a static finding to point at source that Vajra
// itself located and read. A result about a file that is missing, or a line
// past its end, cannot be checked by anything later.
type CodeEvidenceStage struct{}

func (CodeEvidenceStage) Name() string               { return "evidence" }
func (CodeEvidenceStage) FailStatus() finding.Status { return finding.Unconfirmed }

func (CodeEvidenceStage) Check(_ context.Context, f finding.Finding) (finding.Outcome, string) {
	if f.Location == nil || f.Location.File == "" || f.Location.Line < 1 {
		return finding.Fail, "the scanner gave no file and line"
	}
	if f.Evidence.Code == "" {
		return finding.Fail, "the reported file and line could not be read from the source tree"
	}
	return finding.Pass, "source located and read"
}

// SourceScopeStage rejects findings whose file lies outside the source tree
// that was handed over for analysis.
type SourceScopeStage struct{}

func (SourceScopeStage) Name() string               { return "scope" }
func (SourceScopeStage) FailStatus() finding.Status { return finding.OutOfScope }

func (SourceScopeStage) Check(_ context.Context, f finding.Finding) (finding.Outcome, string) {
	if f.Location == nil || !finding.SafeRelPath(f.Location.File) {
		return finding.Fail, "the file is not inside the analysed source tree"
	}
	return finding.Pass, "file is inside the analysed source tree"
}

// PackageEvidenceStage requires a dependency finding to name the package and
// version it is about.
type PackageEvidenceStage struct{}

func (PackageEvidenceStage) Name() string               { return "evidence" }
func (PackageEvidenceStage) FailStatus() finding.Status { return finding.Unconfirmed }

func (PackageEvidenceStage) Check(_ context.Context, f finding.Finding) (finding.Outcome, string) {
	if len(f.Evidence.Extracted) == 0 || f.Evidence.Extracted[0] == "" {
		return finding.Fail, "the finding does not name a package and version"
	}
	return finding.Pass, "package and version identified: " + f.Evidence.Extracted[0]
}
