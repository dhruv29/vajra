package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/fix"
	"github.com/dhruv29/vajra/internal/llm"
	"github.com/dhruv29/vajra/internal/notify"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/semgrep"
)

// Fix proposes a change for one code finding of a saved run and checks it by
// re-running the rule on a patched copy of the file. The source tree is not
// modified; the result carries a patch for a person to review.
func Fix(ctx context.Context, cfg config.Config, deps Deps, run record.Run, findingID string) (fix.Result, error) {
	if deps.Runner == nil || deps.Getenv == nil {
		return fix.Result{}, errors.New("app: a sandbox runner and an environment lookup are required")
	}
	deps = withDefaults(deps)
	if cfg.Source == nil || cfg.Source.Semgrep == nil {
		return fix.Result{}, errors.New("app: fixing needs source.semgrep in the configuration, to re-check the patched code")
	}
	if cfg.Refuter.Provider != config.RefuterAnthropic {
		return fix.Result{}, errors.New("app: fixing needs refuter.provider \"anthropic\", to propose the change")
	}
	target, ok := findingByID(run, findingID)
	if !ok {
		return fix.Result{}, fmt.Errorf("app: run %s has no finding %q", run.ID, findingID)
	}
	if target.Source != semgrep.Source {
		return fix.Result{}, errors.New("app: only findings from code analysis can be fixed automatically")
	}
	key := deps.Getenv(cfg.Refuter.APIKeyEnv)
	if key == "" {
		return fix.Result{}, fmt.Errorf("app: proposing a fix needs an API key in the %s environment variable", cfg.Refuter.APIKeyEnv)
	}
	b, err := budget.New(cfg.Budget, deps.Now)
	if err != nil {
		return fix.Result{}, err
	}
	model, err := llm.NewClient(llm.Options{APIKey: key, Model: cfg.Refuter.Model, BaseURL: deps.ModelBaseURL, HTTP: deps.ModelClient})
	if err != nil {
		return fix.Result{}, err
	}
	scanner := semgrep.Scanner{
		Runner: budgetRunner{inner: deps.Runner, budget: b}, Image: cfg.Source.Semgrep.Image,
		RulesHostDir: cfg.Source.Semgrep.RulesHostDir, RulesImagePath: cfg.Source.Semgrep.RulesImagePath,
		Timeout: time.Duration(cfg.Source.Semgrep.TimeoutSeconds) * time.Second,
	}
	rescan := func(ctx context.Context, root, relPath string) ([]finding.Finding, error) {
		onCopy := scanner
		onCopy.SourceRoot = root
		return onCopy.ScanFile(ctx, relPath)
	}
	return fix.Attempt(ctx, cfg.Source.Root, target, fix.ModelProposer{Model: model, Budget: b}, rescan)
}

func findingByID(run record.Run, id string) (finding.Finding, bool) {
	for _, f := range run.Report.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// Exposure looks up the packages a saved run recorded and returns advisories
// that were not in that run: vulnerabilities published since, matched to what
// is already known to be deployed, without scanning anything again.
func Exposure(ctx context.Context, deps Deps, run record.Run) ([]finding.Finding, error) {
	packages := run.Report.Activity.Packages
	if len(packages) == 0 {
		return nil, errors.New("app: this run recorded no dependency inventory; scan with source.dependencies.osv enabled")
	}
	client := osv.NewClient(osv.Options{BaseURL: deps.OSVBaseURL, HTTP: deps.ModelClient})
	advisories, err := client.Query(ctx, packages)
	if err != nil {
		return nil, fmt.Errorf("dependency lookup: %w", err)
	}
	known := map[string]bool{}
	for _, f := range run.Report.Findings {
		known[f.ID] = true
	}
	fresh := []finding.Finding{}
	for _, f := range osv.Findings(packages, advisories) {
		if !known[f.ID] {
			fresh = append(fresh, f)
		}
	}
	return fresh, nil
}

// Notify posts a short summary of the run to the configured webhook. It sends
// counts and the titles of the top findings, never evidence.
func Notify(ctx context.Context, cfg config.Config, deps Deps, run record.Run) error {
	if cfg.Notify == nil {
		return errors.New("app: no notification is configured")
	}
	if deps.Getenv == nil {
		return errors.New("app: an environment lookup is required")
	}
	webhook := deps.Getenv(cfg.Notify.WebhookURLEnv)
	if webhook == "" {
		return fmt.Errorf("app: the webhook URL is expected in the %s environment variable", cfg.Notify.WebhookURLEnv)
	}
	return notify.Send(ctx, notify.Summarize(run), notify.Options{URL: webhook, AllowPrivate: cfg.Notify.AllowPrivate, HTTP: deps.ModelClient})
}
