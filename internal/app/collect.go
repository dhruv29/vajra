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
	"github.com/dhruv29/vajra/internal/har"
	"github.com/dhruv29/vajra/internal/nuclei"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/recon"
	"github.com/dhruv29/vajra/internal/redact"
	"github.com/dhruv29/vajra/internal/secrets"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	maxEndpointsKept = 300
	// defaultRecordingTargets is how many recorded pages are scanned when the
	// configuration does not say.
	defaultRecordingTargets = 200
	maxLeads                = 40
)

func bytesReader(raw []byte) io.Reader { return bytes.NewReader(raw) }

// collect runs every enabled scanner, in an order where each can use what the
// earlier ones found, and returns the raw candidates. Any scanner failing
// fails the run: a broken scan must never look like a clean one.
func (r *run) collect(ctx context.Context) ([]finding.Finding, error) {
	var candidates []finding.Finding
	stages := []func(context.Context) ([]finding.Finding, error){
		r.discover, r.importRecording, r.crawlTargets, r.scanTargets, r.checkAccess, r.testAPI, r.testGraphQL, r.findOpenPorts,
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

// importRecording adds the in-scope pages of a browser recording to the
// targets. The recording is treated as untrusted input: every address in it
// is checked against the scope, and none of its cookies, credentials or body
// values are kept.
func (r *run) importRecording(context.Context) ([]finding.Finding, error) {
	if r.cfg.Recording == nil {
		return nil, nil
	}
	raw, err := r.deps.ReadFile(r.cfg.Recording.Path)
	if err != nil {
		return nil, fmt.Errorf("recording: %w", err)
	}
	recording, err := har.Parse(bytes.NewReader(raw), r.policy, har.Options{})
	if err != nil {
		return nil, fmt.Errorf("recording: %w", err)
	}
	limit := r.cfg.Recording.MaxTargets
	if limit == 0 {
		limit = defaultRecordingTargets
	}
	known := map[string]bool{}
	for _, target := range r.targets {
		known[target] = true
	}
	added := 0
	for _, pageURL := range recording.URLs {
		if known[pageURL] {
			continue
		}
		if added == limit {
			r.note("The recording holds more pages than the limit of %d, so the rest were not scanned.", limit)
			break
		}
		known[pageURL] = true
		r.targets = append(r.targets, pageURL)
		added++
		if len(r.activity.Endpoints) < maxEndpointsKept {
			r.activity.Endpoints = append(r.activity.Endpoints, pageURL)
		}
	}
	r.noteRecording(recording, added)
	return nil, nil
}

// noteRecording says what the recording contributed and what was left out, so
// a recording that added nothing is not mistaken for one that was scanned.
func (r *run) noteRecording(recording har.Recording, added int) {
	changing := 0
	for _, request := range recording.Requests {
		if request.StateChanging {
			changing++
		}
	}
	r.note("The browser recording added %d page(s) to the scan. %d recorded request(s) change state and were not replayed.", added, changing)
	skipped := recording.Skipped
	if skipped.OutOfScope > 0 {
		r.note("%d recorded request(s) were outside the scope and were dropped.", skipped.OutOfScope)
	}
	if unread := skipped.Malformed + skipped.UnsupportedScheme + skipped.OverLimit; unread > 0 {
		r.note("%d recorded request(s) could not be used (malformed, not http, or over the limit).", unread)
	}
}

func (r *run) note(format string, args ...any) {
	r.activity.Notes = append(r.activity.Notes, fmt.Sprintf(format, args...))
}

// inScope reports whether a URL may be requested.
func (r *run) inScope(rawURL string) bool {
	host, port, err := verify.TargetHostPort(rawURL)
	return err == nil && r.policy.CheckTarget(host, port) == nil
}

// inAccountScope is the scope for anything that sends the scanning account's
// credentials: in scope, and one of the hosts the account was issued for.
func (r *run) inAccountScope(rawURL string) bool {
	return r.inScope(rawURL) && r.accountMayReach(rawURL)
}

// crawlTargets follows links from the targets to learn the application's
// endpoints.
func (r *run) crawlTargets(ctx context.Context) ([]finding.Finding, error) {
	if r.cfg.Crawl == nil || len(r.targets) == 0 {
		return nil, nil
	}
	result, err := crawl.Crawl(ctx, r.fetcher, r.cfg.Targets, crawl.Options{
		MaxPages: r.cfg.Crawl.MaxPages, MaxDepth: r.cfg.Crawl.MaxDepth, InScope: r.inAccountScope, Headers: r.scanHeaders,
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

// scanTargets runs the live scanner. With a scanning account, the targets the
// operator listed are scanned as that account and any discovered hosts are
// scanned without credentials.
func (r *run) scanTargets(ctx context.Context) ([]finding.Finding, error) {
	if r.nuclei == nil || len(r.targets) == 0 {
		return nil, nil
	}
	groups := map[*nuclei.Scanner][]string{}
	for _, target := range r.targets {
		scanner := r.scannerFor(target)
		groups[scanner] = append(groups[scanner], target)
	}
	var found []finding.Finding
	for _, scanner := range []*nuclei.Scanner{r.nuclei, r.nucleiAnon} {
		if scanner == nil || len(groups[scanner]) == 0 {
			continue
		}
		before := scanner.Skipped()
		results, err := scanner.Scan(ctx, groups[scanner])
		if err != nil {
			return nil, err
		}
		if skipped := scanner.Skipped() - before; skipped > 0 {
			r.note("The scanner produced %d result line(s) that could not be read, for example because a response was too large. Those results are missing, so this scan is incomplete.", skipped)
		}
		found = append(found, results...)
	}
	return found, nil
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

func (r *run) testGraphQL(ctx context.Context) ([]finding.Finding, error) {
	if r.graphql == nil {
		return nil, nil
	}
	return r.graphql.Run(ctx)
}

// findOpenPorts tries the configured hosts and ports through the gate and
// reports the open ones the operator did not expect.
func (r *run) findOpenPorts(ctx context.Context) ([]finding.Finding, error) {
	if r.ports == nil {
		return nil, nil
	}
	result, err := r.ports.Scan(ctx)
	if err != nil {
		return nil, err
	}
	if len(result.Refused) > 0 {
		r.note("The gate refused %d address(es) during port discovery, so they were not checked: %s.",
			len(result.Refused), strings.Join(result.Refused, ", "))
	}
	found := make([]finding.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		f.Kind = finding.Network
		found = append(found, f)
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
	if err := r.budget.Check(); err != nil {
		return nil, err
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
		Model: r.model, Fetcher: r.fetcher, Budget: r.budget, InScope: r.inAccountScope,
		Approve: r.approver(), Stop: r.deps.Stop, Pause: r.deps.Pause,
		Headers: r.scanHeaders, SecretHeaders: r.secretHeaders, SecretValues: r.secretValues,
		MaxSteps: r.cfg.Agent.MaxSteps, Goal: r.cfg.Agent.Goal, Targets: r.cfg.Targets,
		Leads: r.leads(known), Known: titles(known, finding.Dynamic),
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

// leads are hints for the explorer from the other scanners: weaknesses that
// code analysis suggests, to be demonstrated live, and pages the crawl found.
// They are handed over as data, separate from the operator's own goal.
func (r *run) leads(known []finding.Finding) []string {
	var out []string
	for _, title := range titles(known, finding.Static) {
		out = append(out, "code analysis suggests: "+title)
	}
	for i, endpoint := range r.activity.Endpoints {
		if i >= maxLeads {
			break
		}
		out = append(out, "page found by crawling: "+endpoint)
	}
	return out
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

// scrub removes every account's credential value from text.
func (r *run) scrub(text string) string {
	return redact.Values(text, r.secretValues...)
}

// redact removes credentials from every finding before it is verified, stored
// or shown to a model: header lines by name, and the credential values
// themselves wherever a target or a tool repeated them.
func (r *run) redact(findings []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		f.Evidence.Request = redact.Headers(f.Evidence.Request, r.secretHeaders...)
		f.Evidence.Response = redact.Headers(f.Evidence.Response, r.secretHeaders...)
		out = append(out, r.scrubFinding(f))
	}
	return out
}

func (r *run) scrubFinding(f finding.Finding) finding.Finding {
	if len(r.secretValues) == 0 {
		return f
	}
	f.Title, f.Description = r.scrub(f.Title), r.scrub(f.Description)
	e := f.Evidence
	e.Request, e.Response, e.Code = r.scrub(e.Request), r.scrub(e.Response), r.scrub(e.Code)
	e.MatchedAt, e.Matcher = r.scrub(e.MatchedAt), r.scrub(e.Matcher)
	extracted := make([]string, 0, len(e.Extracted))
	for _, value := range e.Extracted {
		extracted = append(extracted, r.scrub(value))
	}
	e.Extracted = extracted
	f.Evidence = e
	verdicts := make([]finding.Verdict, 0, len(f.Verdicts))
	for _, v := range f.Verdicts {
		v.Reason = r.scrub(v.Reason)
		verdicts = append(verdicts, v)
	}
	f.Verdicts = verdicts
	return f
}

// scrubActivity removes credentials from what the run recorded about itself.
func (r *run) scrubActivity() {
	a := &r.activity
	for i := range a.Notes {
		a.Notes[i] = r.scrub(a.Notes[i])
	}
	for i := range a.Endpoints {
		a.Endpoints[i] = r.scrub(a.Endpoints[i])
	}
	for i := range a.AgentSteps {
		a.AgentSteps[i].Summary, a.AgentSteps[i].Outcome = r.scrub(a.AgentSteps[i].Summary), r.scrub(a.AgentSteps[i].Outcome)
	}
	a.AgentSummary = r.scrub(a.AgentSummary)
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
