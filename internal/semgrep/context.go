package semgrep

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	contextLines   = 6
	maxSourceBytes = 4 << 20
	maxLineChars   = 300
)

// readContext returns the lines around a finding, numbered, with the reported
// lines marked. It opens the file through os.Root, so a path or a symbolic
// link that leads out of the source tree is refused. An unreadable file gives
// "", and the finding then fails the evidence check.
func readContext(sourceRoot string, loc *finding.Location) string {
	if loc == nil || !finding.SafeRelPath(loc.File) || loc.Line < 1 {
		return ""
	}
	root, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return ""
	}
	defer root.Close()
	f, err := root.Open(loc.File)
	if err != nil {
		return ""
	}
	defer f.Close()

	first, last := max(1, loc.Line-contextLines), max(loc.Line, loc.EndLine)+contextLines
	var b strings.Builder
	scanner := bufio.NewScanner(io.LimitReader(f, maxSourceBytes))
	scanner.Buffer(make([]byte, 0, 64<<10), maxSourceBytes)
	reported := false
	for n := 1; scanner.Scan() && n <= last; n++ {
		if n < first {
			continue
		}
		marker := " "
		if n >= loc.Line && n <= max(loc.Line, loc.EndLine) {
			marker, reported = ">", true
		}
		text := scanner.Text()
		if len(text) > maxLineChars {
			text = text[:maxLineChars] + " [line truncated]"
		}
		fmt.Fprintf(&b, "%s %5d | %s\n", marker, n, text)
	}
	if !reported {
		return "" // the file is shorter than the reported line
	}
	return b.String()
}
