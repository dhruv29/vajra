package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/blast"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/crawl"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/recon"
	"github.com/dhruv29/vajra/internal/redact"
	"github.com/dhruv29/vajra/internal/secrets"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	maxEndpointsKept = 300
	maxLeads         = 40
)

func bytesReader(raw []byte) io.Reader { return bytes.NewReader(raw) }

// collect runs every enabled scanner, in an order where each can use what the
// earlier ones found, and returns the raw candidates. Any scanner failing
// fails the run: a broken scan must never look like a clean one.
func (r *run) collect(ctx context.Context) ([]finding.Finding, error) {
	var candidates []finding.Finding
	stages := []func(context.Context) ([]finding.Finding, error){
		r.discover, r.crawlTargets, r.scanTargets, r.checkAccess, r.testAPI,
		r.analyseCode, r.findSecrets, r.checkDependencies,
	}
	for _, stage := range stages {
		found, err := stage(ctx)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, found...)
	}
	// The agent goes last so that it can be told what is already known.
	found, err := r.explore(ctx, candidates)
	if err != nil {
		return nil, err
	}
	return r.redact(append(candidates, found...)), nil
}

// discover looks for hosts under wildcard scope entries and adds them as
// targets.
func (r *run) discover(ctx context.Context) ([]finding.Finding, error) {
	if r.cfg.Recon == nil {
		return nil, nil
	}
	result, err := recon.Discover(ctx, r.policy, recon.Options{
		Resolver: r.deps.Resolver, Words: r.cfg.Recon.Words, MaxNames: r.cfg.Recon.MaxNames,
	})
	if err != nil {
		return nil, err
	}
	for _, host := range result.Hosts {
		r.activity.DiscoveredHosts = append(r.activity.DiscoveredHosts, host.Name)
	}
	r.activity.RejectedHosts = result.Rejected
	for _, base := range result.CatchAll {
		r.note("Every name under %s resolves, so host discovery was skipped there.", base)
	}
	known := map[string]bool{}
	for _, t := range r.targets {
		known[t] = true
	}
	for _, u := range recon.URLs(r.policy, result.Hosts) {
		if !known[u] {
			r.targets = append(r.targets, u)
		}
	}
	return nil, nil
}

func (r *run) note(format string, args ...any) {
	r.activity.Notes = append(r.activity.Notes, fmt.Sprintf(format, args...))
}

// inScope reports whether a URL may be requested.
func (r *run) inScope(rawURL string) bool {
	host, port, err := verify.TargetHostPort(rawURL)
	return err == nil && r.policy.CheckTarget(host, port) == nil
}

// crawlTargets follows links from the targets to learn the application's
// endpoints.
func (r *run) crawlTargets(ctx context.Context) ([]finding.Finding, error) {
	if r.cfg.Crawl == nil || len(r.targets) == 0 {
		return nil, nil
	}
	result, err := crawl.Crawl(ctx, r.fetcher, r.targets, crawl.Options{
		MaxPages: r.cfg.Crawl.MaxPages, MaxDepth: r.cfg.Crawl.MaxDepth, InScope: r.inScope, Headers: r.scanHeaders,
	})
	if err != nil {
		return nil, fmt.Errorf("crawl: %w", err)
	}
	r.activity.PagesCrawled, r.activity.CrawlTruncated = len(result.Pages), result.Truncated
	for _, page := range result.Pages {
		if page.Error == "" && len(r.activity.Endpoints) < maxEndpointsKept {
			r.activity.Endpoints = append(r.activity.Endpoints, page.URL)
		}
	}
	if result.Truncated {
		r.note("Crawling stopped at the page limit of %d with links still unvisited.", r.cfg.Crawl.MaxPages)
	}
	return nil, nil
}

func (r *run) scanTargets(ctx context.Context) ([]finding.Finding, error) {
	if r.nuclei == nil || len(r.targets) == 0 {
		return nil, nil
	}
	return r.nuclei.Scan(ctx, r.targets)
}

func (r *run) checkAccess(ctx context.Context) ([]finding.Finding, error) {
	if r.checker == nil {
		return nil, nil
	}
	return r.checker.Run(ctx)
}

func (r *run) testAPI(ctx context.Context) ([]finding.Finding, error) {
	if r.api == nil {
		return nil, nil
	}
	found, err := r.api.Run(ctx)
	if err != nil {
		return nil, err
	}
	for _, skipped := range r.api.Skipped {
		r.activity.SkippedOperations = append(r.activity.SkippedOperations, skipped.Operation+": "+skipped.Reason)
	}
	return found, nil
}

func (r *run) analyseCode(ctx context.Context) ([]finding.Finding, error) {
	if r.semgrep == nil {
		return nil, nil
	}
	return r.semgrep.Scan(ctx)
}

func (r *run) findSecrets(context.Context) ([]finding.Finding, error) {
	if r.cfg.Source == nil || !r.cfg.Source.Secrets {
		return nil, nil
	}
	found, err := secrets.Scan(r.cfg.Source.Root)
	if err != nil {
		return nil, err
	}
	for i := range found {
		found[i].AssetURL = r.cfg.Source.Serves
	}
	return found, nil
}

func (r *run) checkDependencies(ctx context.Context) ([]finding.Finding, error) {
	if r.osv == nil {
		return nil, nil
	}
	packages, err := osv.Inventory(r.cfg.Source.Root)
	if err != nil {
		return nil, err
	}
	r.activity.Packages = packages
	if len(packages) == 0 {
		r.note("No lockfile with pinned packages was found, so no dependencies were checked.")
		return nil, nil
	}
	advisories, err := r.osv.client.Query(ctx, packages)
	if err != nil {
		return nil, fmt.Errorf("dependency lookup: %w", err)
	}
	for _, pkg := range packages {
		r.osv.packages[pkg.Ecosystem+"/"+pkg.Name+"@"+pkg.Version] = pkg
	}
	found := osv.Findings(packages, advisories)
	for i := range found {
		found[i].AssetURL = r.cfg.Source.Serves
	}
	return found, nil
}

// explore runs the autonomous explorer, briefed with what the other scanners
// found so that code findings steer the live testing.
func (r *run) explore(ctx context.Context, known []finding.Finding) ([]finding.Finding, error) {
	if r.cfg.Agent == nil {
		return nil, nil
	}
	var err error
	r.explorer, err = agent.NewExplorer(agent.Options{
		Model: r.model, Fetcher: r.fetcher, Budget: r.budget, InScope: r.inScope,
		Approve: r.approver(), Stop: r.deps.Stop,
		Headers: r.scanHeaders, SecretHeaders: r.secretHeaders,
		MaxSteps: r.cfg.Agent.MaxSteps, Goal: r.goal(known), Targets: r.targets, Known: titles(known, finding.Dynamic),
	})
	if err != nil {
		return nil, err
	}
	result, err := r.explorer.Explore(ctx)
	r.activity.AgentSteps, r.activity.AgentStopped, r.activity.AgentSummary = result.Steps, result.Stopped, result.Summary
	if err != nil {
		// What it reported before failing is still verified.
		r.note("The autonomous exploration ended early: %v", err)
	}
	return result.Candidates, nil
}

// approver refuses every request that could change data unless the operator
// asked to be consulted.
func (r *run) approver() agent.Approver {
	if r.cfg.Agent.UnsafeRequests == config.UnsafeAsk {
		return r.deps.Approve
	}
	return agent.DenyAll
}

// goal combines the operator's goal with leads from code analysis and
// crawling, so the agent tries to demonstrate live what the code suggests.
func (r *run) goal(known []finding.Finding) string {
	var b strings.Builder
	b.WriteString(r.cfg.Agent.Goal)
	leads := titles(known, finding.Static)
	if len(leads) > 0 {
		b.WriteString(" Code analysis suggests these weaknesses; try to demonstrate them against the running service: ")
		b.WriteString(strings.Join(leads, "; "))
		b.WriteString(".")
	}
	if n := len(r.activity.Endpoints); n > 0 {
		b.WriteString(" Pages found by crawling: ")
		b.WriteString(strings.Join(r.activity.Endpoints[:min(n, maxLeads)], " "))
	}
	return b.String()
}

func titles(findings []finding.Finding, kind finding.Kind) []string {
	var out []string
	for _, f := range findings {
		if f.Kind == kind && len(out) < maxLeads {
			out = append(out, f.Title+" ("+f.Target+")")
		}
	}
	return out
}

// redact removes credentials from the captured traffic of every finding
// before it is verified, stored or shown to a model.
func (r *run) redact(findings []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		f.Evidence.Request = redact.Headers(f.Evidence.Request, r.secretHeaders...)
		f.Evidence.Response = redact.Headers(f.Evidence.Response, r.secretHeaders...)
		out = append(out, f)
	}
	return out
}

// corroborate links findings that show the same weakness on the same service
// from both sides: one from the code and one from the running application.
// Each is stronger evidence for the other.
func corroborate(findings []finding.Finding) []finding.Finding {
	type key struct {
		service    string
		capability blast.Capability
	}
	needsAttention := func(f finding.Finding) bool {
		return f.Status == finding.Confirmed || f.Status == finding.Unconfirmed
	}
	byKey := map[key][]int{}
	for i, f := range findings {
		capability, _ := blast.Classify(f)
		service := serviceOf(f)
		if !needsAttention(f) || service == "" || capability == blast.Unclassified || f.Kind == finding.Dependency {
			continue
		}
		byKey[key{service, capability}] = append(byKey[key{service, capability}], i)
	}
	out := append([]finding.Finding{}, findings...)
	for _, group := range byKey {
		for _, i := range group {
			for _, j := range group {
				if out[i].Kind != out[j].Kind {
					out[i].CorroboratedBy = append(out[i].CorroboratedBy, out[j].ID)
				}
			}
		}
	}
	return out
}

// serviceOf names the scheme, host and port a finding belongs to. The port is
// always written out, so "https://app.test" and "https://app.test:443" are
// recognised as the same service.
func serviceOf(f finding.Finding) string {
	anchor := f.Target
	if f.AssetURL != "" {
		anchor = f.AssetURL
	}
	host, port, err := verify.TargetHostPort(anchor)
	if err != nil {
		return ""
	}
	u, _ := url.Parse(anchor)
	return strings.ToLower(u.Scheme+"://"+host) + ":" + strconv.Itoa(int(port))
}
