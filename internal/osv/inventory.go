package osv

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	maxLockfileBytes = 20 << 20
	maxPackages      = 20_000
)

// ErrTooManyPackages is returned by Inventory, together with the packages
// read so far, when a tree pins more packages than Inventory will collect.
// The caller can then say that the inventory is incomplete instead of
// presenting a partial one as the whole.
var ErrTooManyPackages = errors.New("osv: the source tree pins too many packages; the inventory is incomplete")

// skippedDirs hold version control data, build output or installed copies of
// dependencies. What a project pins is recorded in its own lockfiles, not in
// those of the packages it has downloaded.
var skippedDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".venv": true, "target": true,
}

// lockfileParser reads one lockfile format. It fills in everything but File.
type lockfileParser func(text string) []Package

func parserFor(name string) lockfileParser {
	switch {
	case name == "go.mod":
		return parseGoMod
	case name == "package-lock.json":
		return parsePackageLock
	case name == "Cargo.lock":
		return parseCargoLock
	case name == "Gemfile.lock":
		return parseGemfileLock
	case strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"):
		return parseRequirements
	}
	return nil
}

// Inventory reads the lockfiles under root and returns the pinned packages,
// sorted and de-duplicated. The tree is read through os.Root, so a symbolic
// link that leads out of it is not followed. Files and directories that
// cannot be read or parsed are skipped.
func Inventory(root string) ([]Package, error) {
	tree, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("osv: open source tree: %w", err)
	}
	defer tree.Close()

	var found []Package
	truncated := false
	walkErr := fs.WalkDir(tree.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return dirAction(entry, err)
		}
		parse := parserFor(entry.Name())
		if parse == nil {
			return nil
		}
		found = append(found, readLockfile(tree, path, parse)...)
		if len(found) > maxPackages {
			found, truncated = found[:maxPackages], true
			return fs.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("osv: walk source tree: %w", walkErr)
	}
	found = sortedUnique(found)
	if truncated {
		return found, ErrTooManyPackages
	}
	return found, nil
}

// dirAction decides what the walk does with a directory or an entry it could
// not read: unreadable entries and the directories in skippedDirs are passed
// over, never fatal.
func dirAction(entry fs.DirEntry, err error) error {
	if entry == nil {
		return nil
	}
	if entry.IsDir() && (err != nil || skippedDirs[entry.Name()]) {
		return fs.SkipDir
	}
	return nil
}

// readLockfile parses one lockfile. Anything that is not a regular file of a
// reasonable size inside the tree gives no packages.
func readLockfile(tree *os.Root, path string, parse lockfileParser) []Package {
	name := filepath.FromSlash(path)
	info, err := tree.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxLockfileBytes {
		return nil
	}
	f, err := tree.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()
	// The size was checked above, but the file can grow before it is read.
	raw, err := io.ReadAll(io.LimitReader(f, maxLockfileBytes+1))
	if err != nil || len(raw) > maxLockfileBytes {
		return nil
	}
	pkgs := parse(string(raw))
	for i := range pkgs {
		pkgs[i].File = path
	}
	return pkgs
}

// sortedUnique orders packages and keeps the first pin of each
// ecosystem, name and version: a package pinned by several lockfiles is one
// thing to look up and one thing to report.
func sortedUnique(pkgs []Package) []Package {
	slices.SortStableFunc(pkgs, func(a, b Package) int {
		return cmp.Or(
			cmp.Compare(a.Ecosystem, b.Ecosystem), cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Version, b.Version), cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line),
		)
	})
	return slices.CompactFunc(pkgs, func(a, b Package) bool {
		return a.Ecosystem == b.Ecosystem && a.Name == b.Name && a.Version == b.Version
	})
}
