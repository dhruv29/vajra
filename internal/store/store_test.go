package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func sampleRun(id string) record.Run {
	return record.Run{
		ID: id,
		Report: record.Report{
			Tool: "vajra", GeneratedAt: time.Unix(1_700_000_000, 0).UTC(),
			Authorization: record.Authorization{Operator: "sec@example.test"},
			Targets:       []string{"https://app.test"},
			Summary:       map[finding.Status]int{finding.Confirmed: 1},
			Findings:      []finding.Finding{{ID: "f1", Status: finding.Confirmed}},
		},
		Radii: []blast.Radius{{FindingID: "f1", Score: 72}},
	}
}

func TestSaveThenGetRoundTripsPrivately(t *testing.T) {
	s, dir := open(t)
	const id = "20261121-195440-0a1b2c3d"

	if err := s.Save(sampleRun(id)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(id)

	if err != nil || got.ID != id || got.Report.Findings[0].ID != "f1" || got.Radii[0].Score != 72 {
		t.Fatalf("run = %+v, err = %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "runs", id+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, err = %v; want 0600", info.Mode().Perm(), err)
	}
	if dirInfo, _ := os.Stat(filepath.Join(dir, "runs")); dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v; want 0700", dirInfo.Mode().Perm())
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, "runs", ".run-*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestMalformedIDsNeverTouchTheDisk(t *testing.T) {
	s, _ := open(t)
	for _, id := range []string{"", "../../etc/passwd", "20261121-195440-0a1b2c3d/../x", "run", "20261121-195440-ZZZZZZZZ"} {
		if err := s.Save(sampleRun(id)); err == nil {
			t.Errorf("Save accepted id %q", id)
		}
		if _, err := s.Get(id); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v; want a malformed-id error", id, err)
		}
	}
}

func TestGetReportsMissingAndCorruptRuns(t *testing.T) {
	s, dir := open(t)
	if _, err := s.Get("20261121-195440-0a1b2c3d"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing run: err = %v", err)
	}
	const corrupt = "20261121-195441-0a1b2c3d"
	if err := os.WriteFile(filepath.Join(dir, "runs", corrupt+".json"), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(corrupt); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt run: err = %v", err)
	}
}

func TestListIsNewestFirstAndSkipsJunk(t *testing.T) {
	s, dir := open(t)
	for _, id := range []string{"20261120-100000-aaaaaaaa", "20261121-100000-bbbbbbbb", "20261119-100000-cccccccc"} {
		if err := s.Save(sampleRun(id)); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"20261122-100000-dddddddd.json": "{corrupt", "notes.txt": "x", "other.json": "{}",
	} {
		if err := os.WriteFile(filepath.Join(dir, "runs", name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	list, err := s.List()

	if err != nil || len(list) != 3 {
		t.Fatalf("list = %+v, err = %v", list, err)
	}
	if list[0].ID != "20261121-100000-bbbbbbbb" || list[2].ID != "20261119-100000-cccccccc" {
		t.Fatalf("order = %s ... %s", list[0].ID, list[2].ID)
	}
	if list[0].TopScore != 72 || list[0].Operator != "sec@example.test" || list[0].Counts[finding.Confirmed] != 1 {
		t.Fatalf("summary = %+v", list[0])
	}
}

func TestListOnAnEmptyStoreIsEmptyNotNil(t *testing.T) {
	s, _ := open(t)
	list, err := s.List()
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("list = %v, err = %v", list, err)
	}
}

func TestOpenRequiresAUsableDirectory(t *testing.T) {
	if _, err := Open("  "); err == nil {
		t.Error("an empty data directory was accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file); err == nil {
		t.Error("a file was accepted as the data directory")
	}
}

func TestNewIDSortsByTimeAndIsUnique(t *testing.T) {
	early, _ := NewID(time.Unix(1_700_000_000, 0))
	late, _ := NewID(time.Unix(1_700_000_100, 0))
	same, _ := NewID(time.Unix(1_700_000_000, 0))
	if !idPattern.MatchString(early) || early >= late || early == same {
		t.Fatalf("ids = %s, %s, %s", early, late, same)
	}
}
