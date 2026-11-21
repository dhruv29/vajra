package sarif

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// maxSourceBytes bounds a source file the checker will read. A larger
	// file is an error: the claim is not disproved, just not checked.
	maxSourceBytes = 4 << 20
	// binarySniffBytes is how much of a file is searched for a NUL byte to
	// tell binary from text.
	binarySniffBytes = 8000
	contextLines     = 6
	maxLineChars     = 300
)

var errMissing = errors.New("file does not exist")

// readLines reads a file inside the root as lines without their line
// endings. A file that is absent (or under a path component that is not a
// directory) gives errMissing; anything else that stops the read, including
// a symbolic link out of the tree, is a plain error.
func (c *Checker) readLines(rel string) ([]string, error) {
	root, err := os.OpenRoot(c.root)
	if err != nil {
		return nil, fmt.Errorf("open source root: %w", err)
	}
	defer root.Close()
	f, err := root.Open(rel)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil, errMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSourceBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", rel, maxSourceBytes)
	}
	if bytes.IndexByte(data[:min(len(data), binarySniffBytes)], 0) >= 0 {
		return nil, fmt.Errorf("%s is a binary file", rel)
	}
	return splitLines(string(data)), nil
}

func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// renderContext numbers the lines around loc and marks the cited ones with
// ">", matching the semgrep scanner's Evidence.Code. loc.Line is within
// lines.
func renderContext(lines []string, loc finding.Location) string {
	first := max(1, loc.Line-contextLines)
	last := min(len(lines), loc.EndLine+contextLines)
	var b strings.Builder
	for n := first; n <= last; n++ {
		marker := " "
		if n >= loc.Line && n <= loc.EndLine {
			marker = ">"
		}
		text := lines[n-1]
		if len(text) > maxLineChars {
			text = text[:maxLineChars] + " [line truncated]"
		}
		fmt.Fprintf(&b, "%s %5d | %s\n", marker, n, text)
	}
	return b.String()
}

// regionHasCode reports whether any cited line is something other than
// blank space or a comment. Languages it does not recognise count as code:
// when in doubt the claim is kept.
func regionHasCode(loc finding.Location, lines []string) bool {
	markers := commentMarkers(loc.File)
	for n := loc.Line; n <= min(loc.EndLine, len(lines)); n++ {
		if !isBlankOrComment(lines[n-1], markers) {
			return true
		}
	}
	return false
}

func isBlankOrComment(line string, markers []string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	for _, m := range markers {
		if strings.HasPrefix(line, m) {
			return true
		}
	}
	return false
}

var (
	// cStyle covers line comments and the inside of block comments. "* "
	// (star then space) is a doc-comment continuation; a dereference such as
	// "*p = x" has no space and is still code.
	cStyle    = []string{"//", "/*", "* ", "*/"}
	hashStyle = []string{"#"}
	dashStyle = []string{"--"}

	commentStyles = map[string][]string{
		".go": cStyle, ".js": cStyle, ".jsx": cStyle, ".mjs": cStyle, ".cjs": cStyle,
		".ts": cStyle, ".tsx": cStyle, ".java": cStyle, ".kt": cStyle, ".kts": cStyle,
		".scala": cStyle, ".c": cStyle, ".h": cStyle, ".cc": cStyle, ".cpp": cStyle,
		".hpp": cStyle, ".cs": cStyle, ".swift": cStyle, ".rs": cStyle, ".dart": cStyle,
		".php": cStyle, ".groovy": cStyle,
		".py": hashStyle, ".rb": hashStyle, ".sh": hashStyle, ".bash": hashStyle,
		".zsh": hashStyle, ".pl": hashStyle, ".r": hashStyle, ".yaml": hashStyle,
		".yml": hashStyle, ".toml": hashStyle, ".tf": hashStyle, ".ps1": hashStyle,
		".sql": dashStyle, ".lua": dashStyle, ".hs": dashStyle,
	}
	// hashFiles are extensionless files whose comments start with "#".
	hashFiles = map[string]bool{"dockerfile": true, "makefile": true, "gemfile": true, "rakefile": true}
)

// commentMarkers returns the comment prefixes for a file, or nil when the
// language is not one the checker recognises.
func commentMarkers(file string) []string {
	name := strings.ToLower(path.Base(file))
	if hashFiles[name] || strings.HasPrefix(name, "dockerfile.") {
		return hashStyle
	}
	return commentStyles[path.Ext(name)]
}
