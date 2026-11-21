package verify

import (
	"context"
	"fmt"

	"github.com/dhruv29/vajra/internal/finding"
)

// SourceRouter re-tests a finding with whatever produced it. A run can have
// several scanners; each finding goes back to its own.
type SourceRouter map[string]Reproducer

// Reproduce hands f to the reproducer registered for f.Source. A finding from
// a source with no reproducer cannot be re-tested, which is an error (and so
// an inconclusive stage), never a pass.
func (r SourceRouter) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	reproducer, ok := r[f.Source]
	if !ok || reproducer == nil {
		return false, fmt.Errorf("nothing in this run can re-test findings from %q", f.Source)
	}
	return reproducer.Reproduce(ctx, f)
}
