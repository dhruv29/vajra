package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/bench"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/fix"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/rundiff"
	"github.com/dhruv29/vajra/internal/store"
	"github.com/dhruv29/vajra/internal/topology"
)

const (
	unknownRunID   = "20261121-195440-0a1b2c3d"
	malformedRunID = "../../etc/passwd"
)

// demoKey matches the sample run: its four confirmed findings, and one decoy
// that the sample run refuted.
const demoKey = `{"name": "sample shop", "expectations": [
  {"name": "template injection", "present": true, "cwe": "cwe-94", "rule_contains": "template-injection"},
  {"name": "sql injection", "present": true, "cwe": "cwe-89", "target_contains": "/orders"},
  {"name": "environment file", "present": true, "rule_contains": "exposed-env"},
  {"name": "command injection", "present": true, "kind": "sast", "cwe": "cwe-78"},
  {"name": "admin panel decoy", "present": false, "cwe": "cwe-306"}
]}`

// saveDemo saves the sample run and returns its ID.
func saveDemo(t *testing.T, data string) string {
	t.Helper()
	code, stdout, stderr := invoke("demo", "-data", data)
	if code != exitOK {
		t.Fatalf("demo: code = %d, stderr = %q", code, stderr)
	}
	return strings.SplitN(strings.SplitN(stdout, "saved sample run ", 2)[1], ";", 2)[0]
}

func confirmed(id, title string) finding.Finding {
	return finding.Finding{
		ID: id, Source: "nuclei", RuleID: id, Title: title, Severity: finding.SeverityHigh,
		Target: "https://app.test/" + id, Status: finding.Confirmed,
	}
}

// saveRunWith saves a run holding the given findings and dependency
// inventory, and returns its ID.
func saveRunWith(t *testing.T, data string, packages []osv.Package, findings ...finding.Finding) string {
	t.Helper()
	st, err := store.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.NewID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	report := record.Report{
		Tool: "vajra", Targets: []string{"https://app.test"}, Findings: findings,
		Summary: map[finding.Status]int{}, Activity: record.Activity{Packages: packages},
	}
	run, err := record.Build(id, report, topology.Declaration{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(run); err != nil {
		t.Fatal(err)
	}
	return id
}

// useDeps replaces the dependencies commands build, for one test.
func useDeps(t *testing.T, deps app.Deps) {
	t.Helper()
	previous := newDeps
	newDeps = func() app.Deps { return deps }
	t.Cleanup(func() { newDeps = previous })
}

func TestNewCommandsRejectMissingFlagsAndBadRuns(t *testing.T) {
	cfg := writeFile(t, "run.json", validConfig)
	key := writeFile(t, "key.json", demoKey)
	data := t.TempDir()
	id := saveDemo(t, data)
	noInventory := saveRunWith(t, data, nil)
	missing := filepath.Join(t.TempDir(), "missing")
	cases := map[string][]string{
		"bench without flags":          {"bench"},
		"bench without key":            {"bench", "-data", data, "-run", id},
		"bench unknown run":            {"bench", "-data", data, "-run", unknownRunID, "-key", key},
		"bench malformed run":          {"bench", "-data", data, "-run", malformedRunID, "-key", key},
		"bench unreadable key":         {"bench", "-data", data, "-run", id, "-key", missing},
		"bench malformed key":          {"bench", "-data", data, "-run", id, "-key", cfg},
		"bench threshold out of range": {"bench", "-data", data, "-run", id, "-key", key, "-min-recall", "90"},
		"bench unknown flag":           {"bench", "-nope"},
		"diff without flags":           {"diff"},
		"diff without head":            {"diff", "-data", data, "-base", id},
		"diff unknown base":            {"diff", "-data", data, "-base", unknownRunID, "-head", id},
		"diff unknown head":            {"diff", "-data", data, "-base", id, "-head", unknownRunID},
		"diff malformed run":           {"diff", "-data", data, "-base", malformedRunID, "-head", id},
		"diff unknown format":          {"diff", "-data", data, "-base", id, "-head", id, "-format", "html"},
		"diff unknown flag":            {"diff", "-nope"},
		"keygen without flags":         {"keygen"},
		"keygen without public":        {"keygen", "-private", missing},
		"keygen unknown flag":          {"keygen", "-nope"},
		"sign without flags":           {"sign"},
		"sign without key":             {"sign", "-in", cfg},
		"sign unreadable input":        {"sign", "-in", missing, "-key", cfg},
		"sign unreadable key":          {"sign", "-in", cfg, "-key", missing},
		"sign unknown flag":            {"sign", "-nope"},
		"verify-signature no flags":    {"verify-signature"},
		"verify-signature no public":   {"verify-signature", "-in", cfg, "-sig", cfg},
		"verify-signature no input":    {"verify-signature", "-in", missing, "-sig", cfg, "-public", cfg},
		"verify-signature no sig":      {"verify-signature", "-in", cfg, "-sig", missing, "-public", cfg},
		"verify-signature bad sig":     {"verify-signature", "-in", cfg, "-sig", cfg, "-public", cfg},
		"verify-signature bad flag":    {"verify-signature", "-nope"},
		"fix without flags":            {"fix"},
		"fix without finding":          {"fix", "-config", cfg, "-data", data, "-run", id},
		"fix missing config":           {"fix", "-config", missing, "-data", data, "-run", id, "-finding", "demo-code-cmdi"},
		"fix unknown run":              {"fix", "-config", cfg, "-data", data, "-run", unknownRunID, "-finding", "demo-code-cmdi"},
		"fix malformed run":            {"fix", "-config", cfg, "-data", data, "-run", malformedRunID, "-finding", "demo-code-cmdi"},
		"fix without semgrep config":   {"fix", "-config", cfg, "-data", data, "-run", id, "-finding", "demo-code-cmdi"},
		"fix unknown flag":             {"fix", "-nope"},
		"exposure without flags":       {"exposure"},
		"exposure without run":         {"exposure", "-data", data},
		"exposure unknown run":         {"exposure", "-data", data, "-run", unknownRunID},
		"exposure malformed run":       {"exposure", "-data", data, "-run", malformedRunID},
		"exposure without inventory":   {"exposure", "-data", data, "-run", noInventory},
		"exposure unknown flag":        {"exposure", "-nope"},
		"cleanup unknown flag":         {"cleanup", "-nope"},
		"stop without data":            {"stop"},
		"stop missing directory":       {"stop", "-data", missing},
		"stop unknown flag":            {"stop", "-nope"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := invoke(args...)
			if code != exitError || stderr == "" || stdout != "" {
				t.Fatalf("code = %d, stdout = %q, stderr = %q; want exit %d with only a message", code, stdout, stderr, exitError)
			}
		})
	}
}

func TestUsageListsEveryCommand(t *testing.T) {
	_, stdout, _ := invoke("help")
	for _, command := range []string{"scan", "verify", "gate", "stop", "cleanup", "runs", "report", "serve", "diff",
		"bench", "exposure", "fix", "demo", "keygen", "sign", "verify-signature"} {
		if !strings.Contains(stdout, "  vajra "+command+" ") && !strings.Contains(stdout, "  vajra "+command+"\n") {
			t.Errorf("usage has no synopsis for %q", command)
		}
		if !strings.Contains(stdout, "\n  "+command+" ") {
			t.Errorf("usage has no description for %q", command)
		}
	}
}

func TestBenchScoresARunAgainstAKey(t *testing.T) {
	data := t.TempDir()
	id := saveDemo(t, data)
	key := writeFile(t, "key.json", demoKey)

	code, stdout, stderr := invoke("bench", "-data", data, "-run", id, "-key", key, "-min-precision", "0.9", "-min-recall", "0.9")

	if code != exitOK || stderr != "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{"Benchmark: sample shop", "true positives 4  false positives 0  false negatives 0  true negatives 1", "precision 1.00  recall 1.00"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in:\n%s", want, stdout)
		}
	}
}

func TestBenchUnreviewedSaysWhatItCounted(t *testing.T) {
	data := t.TempDir()
	id := saveDemo(t, data)
	key := writeFile(t, "key.json", demoKey)

	code, stdout, stderr := invoke("bench", "-data", data, "-run", id, "-key", key, "-unreviewed")

	if code != exitOK || stderr != "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "were not reviewed") {
		t.Fatalf("the score does not say unreviewed findings were counted:\n%s", stdout)
	}
}

func TestBenchExitsThreeBelowTheThresholds(t *testing.T) {
	data := t.TempDir()
	id := saveDemo(t, data)
	missed := strings.Replace(demoKey, `{"name": "admin panel decoy"`, `{"name": "request forgery", "present": true, "cwe": "cwe-918"},
  {"name": "admin panel decoy"`, 1)
	key := writeFile(t, "key.json", missed)

	code, stdout, stderr := invoke("bench", "-data", data, "-run", id, "-key", key, "-min-recall", "0.9", "-json")

	if code != exitConfirmed || !strings.Contains(stderr, "below the required") {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	var score bench.Score
	if err := json.Unmarshal([]byte(stdout), &score); err != nil {
		t.Fatalf("stdout is not a score: %v\n%s", err, stdout)
	}
	if score.TruePositives != 4 || score.FalseNegatives != 1 || score.Recall != 0.8 {
		t.Fatalf("score = %+v", score)
	}
	// Without thresholds the same score is only reported.
	if code, _, _ := invoke("bench", "-data", data, "-run", id, "-key", key); code != exitOK {
		t.Fatalf("no thresholds: code = %d", code)
	}
}

func TestDiffShowsWhatIsNewBetweenTwoRuns(t *testing.T) {
	data := t.TempDir()
	old := confirmed("old-issue", "Known issue")
	base := saveRunWith(t, data, nil, old)
	head := saveRunWith(t, data, nil, old, confirmed("new-issue", "Freshly introduced issue"))

	code, stdout, stderr := invoke("diff", "-data", data, "-base", base, "-head", head)
	if code != exitOK || stderr != "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{"Base " + base, "**1 new**, 0 resolved, 1 persisting", "Freshly introduced issue"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in:\n%s", want, stdout)
		}
	}

	code, stdout, _ = invoke("diff", "-data", data, "-base", base, "-head", head, "-format", "json", "-fail-on-new")
	if code != exitConfirmed {
		t.Fatalf("-fail-on-new: code = %d", code)
	}
	var diff rundiff.Diff
	if err := json.Unmarshal([]byte(stdout), &diff); err != nil {
		t.Fatalf("stdout is not a diff: %v\n%s", err, stdout)
	}
	if len(diff.New) != 1 || diff.New[0].Finding.ID != "new-issue" || len(diff.Persisting) != 1 {
		t.Fatalf("diff = %+v", diff)
	}
	// Nothing is new when going back in time, so the gate passes.
	if code, _, _ := invoke("diff", "-data", data, "-base", head, "-head", base, "-fail-on-new"); code != exitOK {
		t.Fatalf("reverse: code = %d", code)
	}
}

// newKeyPair runs keygen and returns the two paths.
func newKeyPair(t *testing.T) (private, public string) {
	t.Helper()
	dir := t.TempDir()
	private, public = filepath.Join(dir, "vajra.key"), filepath.Join(dir, "vajra.pub")
	if code, _, stderr := invoke("keygen", "-private", private, "-public", public); code != exitOK {
		t.Fatalf("keygen: code = %d, stderr = %q", code, stderr)
	}
	return private, public
}

func TestKeygenWritesAKeyPairAndNeverOverwritesOne(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "vajra.key"), filepath.Join(dir, "vajra.pub")

	code, stdout, stderr := invoke("keygen", "-private", private, "-public", public)

	if code != exitOK || !strings.Contains(stdout, private) || !strings.Contains(stdout, public) || !strings.Contains(stdout, "keep the private key safe") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if info, err := os.Stat(private); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key: %v, %v", info, err)
	}
	before, _ := os.ReadFile(private)
	if code, _, stderr := invoke("keygen", "-private", private, "-public", filepath.Join(dir, "other.pub")); code != exitError || stderr == "" {
		t.Fatalf("overwrite: code = %d, stderr = %q", code, stderr)
	}
	if after, _ := os.ReadFile(private); string(after) != string(before) {
		t.Fatal("the existing private key was changed")
	}
}

func TestSignedFileVerifiesUntilItIsChanged(t *testing.T) {
	private, public := newKeyPair(t)
	doc := writeFile(t, "report.json", `{"findings": []}`)

	code, stdout, stderr := invoke("sign", "-in", doc, "-key", private)
	if code != exitOK || !strings.Contains(stdout, doc+".sig") {
		t.Fatalf("sign: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if info, err := os.Stat(doc + ".sig"); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("signature file: %v, %v", info, err)
	}
	var signature struct {
		KeyID string `json:"key_id"`
	}
	raw, _ := os.ReadFile(doc + ".sig")
	if err := json.Unmarshal(raw, &signature); err != nil || signature.KeyID == "" || !strings.Contains(stdout, "key "+signature.KeyID) {
		t.Fatalf("signature = %s, stdout = %q", raw, stdout)
	}

	code, stdout, stderr = invoke("verify-signature", "-in", doc, "-sig", doc+".sig", "-public", public)
	if code != exitOK || !strings.HasPrefix(stdout, "signature is valid (key "+signature.KeyID+", signed 2") {
		t.Fatalf("verify: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}

	_, otherPublic := newKeyPair(t)
	if code, _, stderr := invoke("verify-signature", "-in", doc, "-sig", doc+".sig", "-public", otherPublic); code != exitError || !strings.Contains(stderr, "different key") {
		t.Fatalf("wrong key: code = %d, stderr = %q", code, stderr)
	}
	if err := os.WriteFile(doc, []byte(`{"findings": [], "tampered": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = invoke("verify-signature", "-in", doc, "-sig", doc+".sig", "-public", public)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "changed after signing") {
		t.Fatalf("tampered: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestSignWritesTheSignatureWhereAsked(t *testing.T) {
	private, public := newKeyPair(t)
	doc := writeFile(t, "report.html", "<!doctype html>")
	out := filepath.Join(t.TempDir(), "detached.sig")

	if code, _, stderr := invoke("sign", "-in", doc, "-key", private, "-out", out); code != exitOK {
		t.Fatalf("sign: code = %d, stderr = %q", code, stderr)
	}
	if _, err := os.Stat(doc + ".sig"); err == nil {
		t.Fatal("the default path was written although -out was given")
	}
	if code, _, stderr := invoke("verify-signature", "-in", doc, "-sig", out, "-public", public); code != exitOK {
		t.Fatalf("verify: code = %d, stderr = %q", code, stderr)
	}
	if code, _, _ := invoke("sign", "-in", doc, "-key", private, "-out", filepath.Join(out, "under-a-file.sig")); code != exitError {
		t.Fatalf("unwritable -out: code = %d", code)
	}
}

func TestFixOutcomeDecidesTheExitCode(t *testing.T) {
	patch := "--- a/shop/exports.py\n+++ b/shop/exports.py\n@@ -41 +41 @@\n-old\n+new\n"
	verified := fix.Result{FindingID: "f1", File: "shop/exports.py", Verified: true, Reason: "the rule no longer matches", Explanation: "uses a list\x1b[2K", Patch: patch}
	unverified := fix.Result{FindingID: "f1", File: "shop/exports.py", Reason: "the rule still matches", Patch: patch}
	noPatch := fix.Result{FindingID: "f1", File: "shop/exports.py", Reason: "the proposed change was not usable"}

	t.Run("a verified patch goes to standard output alone", func(t *testing.T) {
		var stdout, stderr strings.Builder
		code, err := reportFix(verified, "", &stdout, &stderr)
		if code != exitOK || err != nil || stdout.String() != patch {
			t.Fatalf("code = %d, err = %v, stdout = %q", code, err, stdout.String())
		}
		for _, want := range []string{"fix for f1 in shop/exports.py: verified", "reason: the rule no longer matches", "explanation: uses a list [2K"} {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("missing %q in %q", want, stderr.String())
			}
		}
	})
	t.Run("an unverified patch is written privately and exits 3", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "fix.patch")
		var stdout, stderr strings.Builder
		code, err := reportFix(unverified, out, &stdout, &stderr)
		if code != exitConfirmed || err != nil || stdout.String() != "" || !strings.Contains(stderr.String(), ": not verified") {
			t.Fatalf("code = %d, err = %v, stdout = %q, stderr = %q", code, err, stdout.String(), stderr.String())
		}
		raw, _ := os.ReadFile(out)
		if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 || string(raw) != patch {
			t.Fatalf("patch file: %v, %v, %q", info, err, raw)
		}
	})
	t.Run("no patch writes nothing", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "fix.patch")
		var stdout, stderr strings.Builder
		code, err := reportFix(noPatch, out, &stdout, &stderr)
		if code != exitOK || err != nil || stdout.String() != "" {
			t.Fatalf("code = %d, err = %v, stdout = %q", code, err, stdout.String())
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatal("an empty patch file was written")
		}
	})
	t.Run("an unwritable patch path is an error", func(t *testing.T) {
		var stdout, stderr strings.Builder
		code, err := reportFix(verified, filepath.Join(t.TempDir(), "no-such-dir", "fix.patch"), &stdout, &stderr)
		if code != exitError || err == nil {
			t.Fatalf("code = %d, err = %v", code, err)
		}
	})
}

// advisoryServer stands in for the advisory database: every queried package
// is affected by one advisory.
func advisoryServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/querybatch" {
			w.Write([]byte(`{"results": [{"vulns": [{"id": "GHSA-test-0001"}]}]}`))
			return
		}
		w.Write([]byte(`{"id": "GHSA-test-0001", "summary": "Request smuggling in lib",
			"database_specific": {"severity": "HIGH"},
			"affected": [{"package": {"name": "example.test/lib", "ecosystem": "Go"}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExposureListsAdvisoriesTheRunDidNotHave(t *testing.T) {
	packages := []osv.Package{{Ecosystem: "Go", Name: "example.test/lib", Version: "1.2.3", File: "go.mod", Line: 5}}
	data := t.TempDir()
	id := saveRunWith(t, data, packages)
	useDeps(t, app.Deps{OSVBaseURL: advisoryServer(t).URL})

	code, stdout, stderr := invoke("exposure", "-data", data, "-run", id)
	if code != exitConfirmed || stderr != "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if lines := strings.Split(strings.TrimSpace(stdout), "\n"); len(lines) != 1 || !strings.HasPrefix(lines[0], "high ") || !strings.Contains(lines[0], "example.test/lib") {
		t.Fatalf("stdout = %q", stdout)
	}

	code, stdout, _ = invoke("exposure", "-data", data, "-run", id, "-json")
	var fresh []finding.Finding
	if err := json.Unmarshal([]byte(stdout), &fresh); err != nil || code != exitConfirmed || len(fresh) != 1 || fresh[0].RuleID != "GHSA-test-0001" {
		t.Fatalf("code = %d, err = %v, stdout = %q", code, err, stdout)
	}

	// A run that already holds the advisory has nothing new to report.
	known := saveRunWith(t, data, packages, fresh[0])
	code, stdout, stderr = invoke("exposure", "-data", data, "-run", known)
	if code != exitOK || stdout != "no new advisories since this run\n" {
		t.Fatalf("known: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if code, stdout, _ := invoke("exposure", "-data", data, "-run", known, "-json"); code != exitOK || strings.TrimSpace(stdout) != "[]" {
		t.Fatalf("known as json: code = %d, stdout = %q", code, stdout)
	}
}

func TestExposureReportsAFailedLookup(t *testing.T) {
	// The default test dependencies point the lookup at a closed port.
	data := t.TempDir()
	id := saveRunWith(t, data, []osv.Package{{Ecosystem: "Go", Name: "example.test/lib", Version: "1.2.3"}})

	if code, stdout, stderr := invoke("exposure", "-data", data, "-run", id); code != exitError || stdout != "" || !strings.Contains(stderr, "dependency lookup") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestCleanupPrintsHowManyContainersItRemoved(t *testing.T) {
	previous := cleanupContainers
	t.Cleanup(func() { cleanupContainers = previous })

	cleanupContainers = func(context.Context) (int, error) { return 3, nil }
	if code, stdout, stderr := invoke("cleanup"); code != exitOK || stdout != "removed 3 leftover sandbox containers\n" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}

	cleanupContainers = func(context.Context) (int, error) { return 0, errors.New("docker is not running") }
	if code, stdout, stderr := invoke("cleanup"); code != exitError || stdout != "" || !strings.Contains(stderr, "docker is not running") {
		t.Fatalf("failure: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestStopCreatesTheStopFileAndCanBeRepeated(t *testing.T) {
	data := t.TempDir()
	requested := stopRequested(data)
	if requested() {
		t.Fatal("stop is requested before anyone asked")
	}

	for attempt := 1; attempt <= 2; attempt++ {
		code, stdout, stderr := invoke("stop", "-data", data)
		if code != exitOK || !strings.Contains(stdout, filepath.Join(data, "STOP")) {
			t.Fatalf("attempt %d: code = %d, stdout = %q, stderr = %q", attempt, code, stdout, stderr)
		}
	}

	info, err := os.Stat(filepath.Join(data, "STOP"))
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		t.Fatalf("stop file: %v, %v", info, err)
	}
	if !requested() {
		t.Fatal("the stop file was not noticed")
	}
	// The stop file must not be mistaken for a run.
	if code, stdout, _ := invoke("runs", "-data", data); code != exitOK || !strings.Contains(stdout, "no saved runs") {
		t.Fatalf("runs: code = %d, stdout = %q", code, stdout)
	}
}

func TestTicketWritesOneFindingAsAnIssue(t *testing.T) {
	data := t.TempDir()
	_, stdout, _ := invoke("demo", "-data", data)
	id := strings.SplitN(strings.SplitN(stdout, "saved sample run ", 2)[1], ";", 2)[0]

	code, out, stderr := invoke("ticket", "-data", data, "-run", id, "-finding", "demo-sqli")

	if code != exitOK || !strings.HasPrefix(out, "[high] SQL injection in order lookup\n\n") || !strings.Contains(out, "**Verification.**") {
		t.Fatalf("code = %d, stderr = %q, out = %.120q", code, stderr, out)
	}
	file := filepath.Join(t.TempDir(), "issue.md")
	if code, _, _ := invoke("ticket", "-data", data, "-run", id, "-finding", "demo-sqli", "-out", file); code != exitOK {
		t.Fatal("writing the ticket to a file failed")
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ticket file: %v, %v", info, err)
	}
	for _, args := range [][]string{{"ticket"}, {"ticket", "-data", data, "-run", id, "-finding", "nope"}, {"ticket", "-data", data, "-run", "bad", "-finding", "x"}} {
		if code, _, stderr := invoke(args...); code == exitOK || stderr == "" {
			t.Errorf("%v: code = %d", args, code)
		}
	}
}
