package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
)

func TestACredentialATargetEchoesInAResponseBodyIsScrubbedFromTheReport(t *testing.T) {
	cfg, policy := labConfig(t, "none", withScanAs)
	env := map[string]string{"USER_TOKEN": userCredential, "TENANT_KEY": "tenant-credential-3"}
	// The response body repeats the Authorization header the scanner sent,
	// as debug and error pages do.
	raw, _ := json.Marshal(map[string]any{
		"template-id": "debug-page", "info": map[string]string{"name": "Debug page for " + userCredential, "severity": "low"},
		"matched-at": "https://app.test/debug", "request": "GET /debug HTTP/1.1\r\nHost: app.test\r\n\r\n",
		"response":          "HTTP/1.1 200 OK\r\n\r\n{\"headers\": {\"Authorization\": \"" + userCredential + "\", \"key\": \"tenant-credential-3\"}}",
		"extracted-results": []string{"token=" + strings.TrimPrefix(userCredential, "Bearer ")},
	})
	runner := &labRunner{respond: site{"GET https://app.test/": htmlPage("<p>home</p>")}.respond}
	runner.scanOutput, runner.reproducible = string(raw)+"\n", map[string]bool{"debug-page": true}

	report, err := Scan(context.Background(), cfg, policy, labDeps(runner, "", env))

	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("findings = %d, err = %v", len(report.Findings), err)
	}
	out, _ := json.Marshal(report)
	for _, secret := range []string{"user-credential-2", "tenant-credential-3"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("%q is in the report", secret)
		}
	}
}

func TestDiscoveredHostsAreScannedWithoutTheAccount(t *testing.T) {
	cfg, policy := labConfig(t, "none", func(m map[string]any) {
		withRecon("https://app.example.test")(m)
		m["auth"] = map[string]any{
			"identities": []map[string]any{{"name": "user", "headers_env": map[string]string{"Authorization": "USER_TOKEN"}}},
			"scan_as":    "user",
		}
	})
	runner := &labRunner{}
	deps := labDeps(runner, "", map[string]string{"USER_TOKEN": userCredential})
	deps.Resolver = zone{names: map[string]string{"www.example.test": "203.0.113.10"}}

	if _, err := Scan(context.Background(), cfg, policy, deps); err != nil {
		t.Fatal(err)
	}

	if len(runner.scanSpecs) != 2 {
		t.Fatalf("scanner runs = %d; want one with the account and one without", len(runner.scanSpecs))
	}
	for _, spec := range runner.scanSpecs {
		targets := strings.Join(scanTargets(spec), " ")
		withAccount := strings.Contains(string(spec.Stdin), userCredential)
		if strings.Contains(targets, "www.example.test") && withAccount {
			t.Fatalf("the account's credential was sent to a discovered host: %s", targets)
		}
		if targets == "https://app.example.test" && !withAccount {
			t.Fatal("the listed target was not scanned as the account")
		}
	}
}

func TestAnInterruptedRunIsAnErrorNotACleanReport(t *testing.T) {
	cfg, policy := loadConfig(t, "none")
	runner := &scriptedRunner{scanOutput: line("real-issue", "high", "https://app.test/b"), reproducible: map[string]bool{"real-issue": true}}
	ctx, cancel := context.WithCancel(context.Background())
	deps := testDeps(runner, "")
	deps.CheckNetwork = func(context.Context, string) error { cancel(); return nil } // interrupted right after start

	report, err := Scan(ctx, cfg, policy, deps)

	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("err = %v; an interrupted run must not return as if it had finished", err)
	}
	for _, f := range report.Findings {
		if f.Status == finding.Confirmed {
			t.Fatalf("a finding was confirmed in an interrupted run: %+v", f)
		}
	}
}

func TestADependencyFindingIsNotConfirmedOnceTheBudgetIsSpent(t *testing.T) {
	cfg, policy := loadConfig(t, "none")
	clock := time.Unix(1_700_000_000, 0)
	deps := testDeps(&scriptedRunner{}, "")
	deps.Now = func() time.Time { return clock }
	r, err := assemble(cfg, policy, deps)
	if err != nil {
		t.Fatal(err)
	}
	reproducer := &osvReproducer{budget: r.budget}
	clock = clock.Add(24 * time.Hour)

	matched, err := reproducer.Reproduce(context.Background(), finding.Finding{Evidence: finding.Evidence{Extracted: []string{"npm/x@1"}}})

	if err == nil || matched {
		t.Fatalf("matched = %v, err = %v; a lookup after the time limit must not confirm anything", matched, err)
	}
}
