// Package app wires the gates, the scanner and the verification pipeline into
// the operations the command line exposes.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/nuclei"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/refute"
	"github.com/dhruv29/vajra/internal/report"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/store"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	gateReadHeaderTimeout = 15 * time.Second
	gateShutdownTimeout   = 10 * time.Second
)

// Deps are the outside-world dependencies of a run, replaceable in tests.
type Deps struct {
	Runner sandbox.Runner
	Getenv func(string) string
	Now    func() time.Time
	// ModelBaseURL and ModelClient override the refuter's endpoint in tests.
	ModelBaseURL string
	ModelClient  *http.Client
}

// Report is the verified output of a run.
type Report = record.Report

// run holds the assembled parts of one run.
type run struct {
	cfg      config.Config
	deps     Deps
	budget   *budget.Budget
	scanner  *nuclei.Scanner
	pipeline *verify.Pipeline
}

func assemble(cfg config.Config, policy *scope.Policy, deps Deps) (*run, error) {
	if deps.Runner == nil || deps.Getenv == nil {
		return nil, errors.New("app: a sandbox runner and an environment lookup are required")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	b, err := budget.New(cfg.Budget, deps.Now)
	if err != nil {
		return nil, err
	}
	scanner := &nuclei.Scanner{
		Runner: deps.Runner, Image: cfg.Nuclei.Image, TemplatesDir: cfg.Nuclei.TemplatesDir,
		Network: cfg.Sandbox.Network, ProxyURL: cfg.Sandbox.ProxyURL,
		Timeout: time.Duration(cfg.Nuclei.TimeoutSeconds) * time.Second, RateLimit: cfg.Nuclei.RateLimit,
	}
	if err := scanner.Validate(); err != nil {
		return nil, err
	}
	refuter, err := newRefuter(cfg.Refuter, deps, b)
	if err != nil {
		return nil, err
	}
	refuteBudget := b
	if cfg.Refuter.Provider == config.RefuterNone {
		refuteBudget = nil // no model call is made, so no turn is charged
	}
	pipeline, err := verify.NewPipeline(deps.Now,
		verify.EvidenceStage{},
		verify.ScopeStage{Policy: policy},
		verify.ReproduceStage{Reproducer: scanner, Attempts: cfg.Verify.ReproduceAttempts, Budget: b},
		verify.RefuteStage{Refuter: refuter, Budget: refuteBudget},
	)
	if err != nil {
		return nil, err
	}
	return &run{cfg: cfg, deps: deps, budget: b, scanner: scanner, pipeline: pipeline}, nil
}

func newRefuter(cfg config.Refuter, deps Deps, b *budget.Budget) (verify.Refuter, error) {
	if cfg.Provider == config.RefuterNone {
		return refute.None{}, nil
	}
	key := deps.Getenv(cfg.APIKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("app: the refuter needs an API key in the %s environment variable", cfg.APIKeyEnv)
	}
	return refute.NewAnthropic(refute.Options{
		APIKey: key, Model: cfg.Model, BaseURL: deps.ModelBaseURL, Client: deps.ModelClient, Budget: b,
	})
}

// Scan runs the scanner against the configured targets and verifies every
// result.
func Scan(ctx context.Context, cfg config.Config, policy *scope.Policy, deps Deps) (Report, error) {
	r, err := assemble(cfg, policy, deps)
	if err != nil {
		return Report{}, err
	}
	if err := r.budget.SpendRun(); err != nil {
		return Report{}, err
	}
	candidates, err := r.scanner.Scan(ctx, cfg.Targets)
	if err != nil {
		return Report{}, err
	}
	return r.verify(ctx, candidates), nil
}

// VerifyOutput verifies scanner output produced earlier, read from in.
func VerifyOutput(ctx context.Context, cfg config.Config, policy *scope.Policy, deps Deps, in io.Reader) (Report, error) {
	r, err := assemble(cfg, policy, deps)
	if err != nil {
		return Report{}, err
	}
	candidates, _, err := nuclei.Parse(in)
	if err != nil {
		return Report{}, err
	}
	return r.verify(ctx, candidates), nil
}

func (r *run) verify(ctx context.Context, candidates []finding.Finding) Report {
	verified := r.pipeline.VerifyAll(ctx, dedupe(candidates))
	sortFindings(verified)
	summary := map[finding.Status]int{}
	for _, f := range verified {
		summary[f.Status]++
	}
	return Report{
		Tool:          "vajra",
		GeneratedAt:   r.deps.Now().UTC(),
		Authorization: record.Authorization(r.cfg.Authorization),
		Targets:       r.cfg.Targets,
		Scope:         r.cfg.Scope,
		Budget:        record.BudgetReport{Limits: r.budget.Limits(), Usage: r.budget.Usage()},
		Refuter:       r.cfg.Refuter.Provider,
		Summary:       summary,
		Findings:      verified,
	}
}

// dedupe keeps the first finding for each ID.
func dedupe(findings []finding.Finding) []finding.Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out
}

var statusOrder = map[finding.Status]int{
	finding.Confirmed: 0, finding.Unconfirmed: 1, finding.Refuted: 2, finding.OutOfScope: 3, finding.Candidate: 4,
}

// sortFindings puts what needs attention first: confirmed, then unconfirmed,
// each by descending severity.
func sortFindings(findings []finding.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if statusOrder[a.Status] != statusOrder[b.Status] {
			return statusOrder[a.Status] < statusOrder[b.Status]
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.ID < b.ID
	})
}

// ServeGate runs the egress proxy on listener until ctx is cancelled. Every
// connection decision is written to audit as one JSON object per line.
func ServeGate(ctx context.Context, policy *scope.Policy, listener net.Listener, audit io.Writer) error {
	guard, err := egress.NewGuard(policy, nil, nil)
	if err != nil {
		return err
	}
	proxy, err := egress.NewProxy(guard, egress.NewJSONLSink(audit))
	if err != nil {
		return err
	}
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: gateReadHeaderTimeout}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	select {
	case err := <-stopped:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gateShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return server.Close()
		}
		return nil
	}
}

// Record turns a report into a stored run: it derives the asset graph and the
// blast radius of each finding, summarises the gate's audit log when one is
// given, and saves the result under dataDir. audit may be nil.
func Record(report Report, cfg config.Config, audit io.Reader, dataDir string, now time.Time) (record.Run, error) {
	st, err := store.Open(dataDir)
	if err != nil {
		return record.Run{}, err
	}
	var events []egress.Event
	if audit != nil {
		if events, err = egress.ReadEvents(audit); err != nil {
			return record.Run{}, err
		}
	}
	id, err := store.NewID(now)
	if err != nil {
		return record.Run{}, err
	}
	run, err := record.Build(id, report, cfg.Topology, events)
	if err != nil {
		return record.Run{}, err
	}
	if err := st.Save(run); err != nil {
		return record.Run{}, err
	}
	return run, nil
}

// Render formats a stored run as "json", "md" or "html".
func Render(run record.Run, format string) ([]byte, error) {
	switch format {
	case "json":
		raw, err := json.MarshalIndent(run, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("app: encode run: %w", err)
		}
		return append(raw, '\n'), nil
	case "md":
		return []byte(report.Markdown(run)), nil
	case "html":
		return report.HTML(run)
	default:
		return nil, fmt.Errorf("app: unknown report format %q: use json, md or html", format)
	}
}
