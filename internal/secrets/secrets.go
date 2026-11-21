// Package secrets finds hard-coded credentials in a source tree. It is a
// native scanner: it needs no sandbox and no external tool, and it never
// copies a secret into a finding.
package secrets

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// Source is the value of Finding.Source for results from this scanner.
	Source = "vajra-secrets"

	// maxFiles bounds one walk, so a huge or generated tree fails loudly
	// instead of running for an unbounded time.
	maxFiles = 50_000
	// maxFileBytes is the largest file that is read. Hand-written source is
	// far smaller; larger files are almost always generated or data.
	maxFileBytes = 1 << 20
	// binarySniffBytes is how much of a file is checked for a NUL byte.
	binarySniffBytes = 8 << 10

	cweHardCodedCredentials = "cwe-798"
	tagSecrets              = "secrets"
)

// skippedDirs hold dependencies, build output or tool state, not the
// project's own source. A secret there is not the project's to fix, and
// these trees are large.
var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".venv": true, "__pycache__": true, "target": true,
}

// errNotScanned marks a file that is deliberately left out: it is not a
// regular file, too large, or binary. A walk passes over such a file, but a
// reproduction must not read it as "the secret is gone".
var errNotScanned = errors.New("not scanned")

// Scan walks the tree under root and returns one candidate finding per secret
// found. Findings are sorted by file, then line, so the output is stable. At
// most maxFindingsPerFile come from one file and maxFindingsPerScan in all;
// past that the walk stops, without an error, with what it has.
func Scan(root string) ([]finding.Finding, error) {
	return scanTree(root, maxFiles)
}

// scanTree is Scan with the file limit as a parameter. The tree is opened
// through os.Root, so a symbolic link or a path that leads out of it is never
// followed.
func scanTree(rootDir string, fileLimit int) ([]finding.Finding, error) {
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("secrets: open source root: %w", err)
	}
	defer root.Close()

	var findings []finding.Finding
	files := 0
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skippedDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil // a symbolic link's target is scanned under its own path, if it is in the tree
		}
		if files++; files > fileLimit {
			return fmt.Errorf("more than %d files under the source root; narrow the scan", fileLimit)
		}
		found, err := scanFile(root, filepath.FromSlash(path))
		if err != nil && !isPassedOver(err) {
			return err
		}
		findings = append(findings, found...)
		if len(findings) >= maxFindingsPerScan {
			findings = findings[:maxFindingsPerScan]
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	slices.SortFunc(findings, byFileThenLine)
	return findings, nil
}

// isPassedOver reports whether a walk may continue after err: the file is out
// of scope, or it was deleted between being listed and being opened.
func isPassedOver(err error) bool {
	return errors.Is(err, errNotScanned) || errors.Is(err, fs.ErrNotExist)
}

func byFileThenLine(a, b finding.Finding) int {
	return cmp.Or(
		strings.Compare(a.Location.File, b.Location.File),
		cmp.Compare(a.Location.Line, b.Location.Line),
		strings.Compare(a.RuleID, b.RuleID),
	)
}

// Reproduce re-scans only f.Location.File and reports whether the same rule
// still matches the same line.
//
// "No match" is reported only when the file was read and scanned. A file that
// is missing, unreadable, outside the tree or no longer scannable is an
// error, because it says nothing about whether the secret is still there.
func Reproduce(root string, f finding.Finding) (bool, error) {
	if f.Location == nil || !finding.SafeRelPath(f.Location.File) {
		return false, errors.New("secrets: the finding has no source location inside the source root")
	}
	tree, err := os.OpenRoot(root)
	if err != nil {
		return false, fmt.Errorf("secrets: open source root: %w", err)
	}
	defer tree.Close()

	found, err := scanFile(tree, f.Location.File)
	if err != nil {
		return false, fmt.Errorf("secrets: re-scan: %w", err)
	}
	for _, again := range found {
		if again.RuleID == f.RuleID && again.Location.Line == f.Location.Line {
			return true, nil
		}
	}
	return false, nil
}

// scanFile reads one file through root and returns its findings. The type is
// checked without following a link, so a link, a pipe or a device is never
// opened.
func scanFile(root *os.Root, name string) ([]finding.Finding, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", errNotScanned, name)
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", errNotScanned, name, maxFileBytes)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// One byte over the limit is read to notice a file that grew after Lstat.
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", errNotScanned, name, maxFileBytes)
	}
	if isBinary(data) {
		return nil, fmt.Errorf("%w: %s is a binary file", errNotScanned, name)
	}
	return analyse(name, splitLines(string(data))), nil
}

func isBinary(data []byte) bool {
	return bytes.IndexByte(data[:min(len(data), binarySniffBytes)], 0) >= 0
}

// splitLines splits text into lines without their endings. A final line with
// no newline is still a line; a trailing newline does not add an empty one.
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
