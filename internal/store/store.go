// Package store keeps runs on disk, one JSON file per run.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dhruv29/vajra/internal/record"
)

const (
	dirMode     = 0o700
	fileMode    = 0o600 // runs hold captured requests and responses
	runsDir     = "runs"
	idRandBytes = 4
	idTimeForm  = "20060102-150405"
)

// ErrNotFound means no run has the requested ID.
var ErrNotFound = errors.New("store: run not found")

// ErrBadID means the ID is not one this store could have issued.
var ErrBadID = errors.New("store: run id is malformed")

var idPattern = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$`)

// Store reads and writes runs under a data directory.
type Store struct {
	dir string
}

// Open prepares the data directory, creating it if needed.
func Open(dataDir string) (*Store, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("store: a data directory is required")
	}
	dir := filepath.Join(dataDir, runsDir)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{dir: dir}, nil
}

// NewID returns a run ID that sorts by time and cannot collide in practice.
func NewID(now time.Time) (string, error) {
	raw := make([]byte, idRandBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: run id: %w", err)
	}
	return now.UTC().Format(idTimeForm) + "-" + hex.EncodeToString(raw), nil
}

func (s *Store) path(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", fmt.Errorf("%w: %q", ErrBadID, id)
	}
	return filepath.Join(s.dir, id+".json"), nil
}

// Save writes a run. It is written to a temporary file first and renamed, so
// a crash cannot leave a half-written run behind.
func (s *Store) Save(run record.Run) error {
	path, err := s.path(run.ID)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode run: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".run-*.tmp")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer os.Remove(tmp.Name()) // no effect after a successful rename
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write run: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: write run: %w", err)
	}
	if err := os.Chmod(tmp.Name(), fileMode); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// Get loads one run.
func (s *Store) Get(id string) (record.Run, error) {
	path, err := s.path(id)
	if err != nil {
		return record.Run{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return record.Run{}, ErrNotFound
	}
	if err != nil {
		return record.Run{}, fmt.Errorf("store: %w", err)
	}
	var run record.Run
	if err := json.Unmarshal(raw, &run); err != nil {
		return record.Run{}, fmt.Errorf("store: run %s is corrupt: %w", id, err)
	}
	return run, nil
}

// List returns a summary of every readable run, newest first. A corrupt file
// is skipped so one bad run cannot hide the others.
func (s *Store) List() ([]record.Summary, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	out := []record.Summary{}
	for _, entry := range entries {
		id, isRun := strings.CutSuffix(entry.Name(), ".json")
		if !isRun || !idPattern.MatchString(id) {
			continue
		}
		run, err := s.Get(id)
		if err != nil {
			continue
		}
		out = append(out, run.Summarize())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}
