// Package app wires the gates, the scanners and the verification pipeline
// into the operations the command line exposes.
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

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/nuclei"
	"github.com/dhruv29/vajra/internal/recon"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/report"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/store"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	gateReadHeaderTimeout = 15 * time.Second
	gateIdleTimeout       = 2 * time.Minute
	gateShutdownTimeout   = 10 * time.Second
)

// Deps are the outside-world dependencies of a run, replaceable in tests.
type Deps struct {
	Runner sandbox.Runner
	// CheckNetwork confirms that the task network has no route out except the
	// gate. It is required whenever anything is tested over the network.
	CheckNetwork func(ctx context.Context, name string) error
	Getenv       func(string) string
	Now          func() time.Time
	// Resolver is used for host discovery. Nil means the system resolver.
	Resolver recon.Resolver
	// Approve is asked before the agent sends a request that could change
	// data. Nil means every such request is refused.
	Approve agent.Approver
	// Stop is polled by the agent between steps; true ends it cleanly.
	Stop func() bool
	// Pause is polled by the agent between steps; while true, it waits.
	Pause func() bool
	// ReadFile reads the API description. Nil means os.ReadFile.
	ReadFile func(path string) ([]byte, error)
	// ModelBaseURL, ModelClient and OSVBaseURL override endpoints in tests.
	ModelBaseURL string
	ModelClient  *http.Client
	OSVBaseURL   string
}

// Report is the verified output of a run.
type Report = record.Report

// Scan runs everything the configuration enables and verifies every result.
func Scan(ctx context.Context, cfg config.Config, policy *scope.Policy, deps Deps) (Report, error) {
	r, err := assemble(cfg, policy, deps)
	if err != nil {
		return Report{}, err
	}
	if err := r.preflight(ctx); err != nil {
		return Report{}, err
	}
	candidates, err := r.collect(ctx)
	if err != nil {
		return Report{}, err
	}
	return r.finish(ctx, r.verify(ctx, candidates))
}

// finish refuses to pass off an interrupted run as a result. Findings that
// were not verified before the interruption are marked unconfirmed, and a
// report in which confirmed findings merely turned unconfirmed could be
// mistaken for a clean one or saved as a baseline.
func (r *run) finish(ctx context.Context, report Report) (Report, error) {
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("app: the run was interrupted before every finding was verified: %w", err)
	}
	return report, nil
}

// VerifyOutput verifies nuclei output produced earlier, read from in.
func VerifyOutput(ctx context.Context, cfg config.Config, policy *scope.Policy, deps Deps, in io.Reader) (Report, error) {
	r, err := assemble(cfg, policy, deps)
	if err != nil {
		return Report{}, err
	}
	if r.nuclei == nil {
		return Report{}, errors.New("app: verifying saved scanner output needs targets in the configuration")
	}
	if err := r.preflight(ctx); err != nil {
		return Report{}, err
	}
	candidates, skipped, err := nuclei.Parse(in)
	if err != nil {
		return Report{}, err
	}
	if skipped > 0 {
		r.note("%d line(s) of the scanner output could not be read and were left out.", skipped)
	}
	return r.finish(ctx, r.verify(ctx, r.redact(candidates)))
}

// pipelineFor picks the verification pipeline for a finding's kind.
func (r *run) pipelineFor(f finding.Finding) *verify.Pipeline {
	switch f.Kind {
	case finding.Static:
		return r.staticPipeline
	case finding.Dependency:
		return r.dependencyPipeline
	case finding.Network:
		return r.networkPipeline
	default:
		return r.dynamicPipeline
	}
}

func (r *run) verify(ctx context.Context, candidates []finding.Finding) Report {
	verified := make([]finding.Finding, 0, len(candidates))
	for _, f := range dedupe(candidates) {
		if pipeline := r.pipelineFor(f); pipeline != nil {
			f = pipeline.Verify(ctx, f)
		} else {
			// Nothing in this run can check a finding of this kind. Say so
			// rather than passing it through looking untouched.
			f = f.WithVerdict(finding.Verdict{
				Stage: "evidence", Outcome: finding.Inconclusive, At: r.deps.Now().UTC(),
				Reason: "this run is not configured to verify " + string(f.Kind) + " findings",
			}).WithStatus(finding.Unconfirmed)
		}
		verified = append(verified, r.scrubFinding(f))
	}
	if err := r.budget.Check(); err != nil {
		r.note("The run stopped early (%v). Findings that were not verified in time are unconfirmed.", err)
	}
	r.scrubActivity()
	verified = corroborate(verified)
	sortFindings(verified)
	summary := map[finding.Status]int{}
	for _, f := range verified {
		summary[f.Status]++
	}
	sourceRoot := ""
	if r.cfg.Source != nil {
		sourceRoot = r.cfg.Source.Root
	}
	return Report{
		Tool:          "vajra",
		GeneratedAt:   r.deps.Now().UTC(),
		Authorization: record.Authorization(r.cfg.Authorization),
		Targets:       r.targets,
		SourceRoot:    sourceRoot,
		Scope:         r.cfg.Scope,
		Budget:        record.BudgetReport{Limits: r.budget.Limits(), Usage: r.budget.Usage()},
		Refuter:       r.cfg.Refuter.Provider,
		Summary:       summary,
		Findings:      verified,
		Activity:      r.activity,
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

// ServeGate runs the egress gate until ctx is cancelled. listener serves the
// HTTP proxy. socks, when not nil, also serves SOCKS5 for tools that speak
// raw TCP; both enforce the same policy and write to the same audit log, one
// JSON object per line.
func ServeGate(ctx context.Context, policy *scope.Policy, listener, socks net.Listener, audit io.Writer) error {
	guard, err := egress.NewGuard(policy, nil, nil)
	if err != nil {
		return err
	}
	sink := egress.NewJSONLSink(audit)
	proxy, err := egress.NewProxy(guard, sink)
	if err != nil {
		return err
	}
	// Everything that can fail is built before anything starts serving, so an
	// error here leaves nothing running.
	var socksServer *egress.SOCKS5
	if socks != nil {
		if socksServer, err = egress.NewSOCKS5(guard, sink); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopped := make(chan error, 2)
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: gateReadHeaderTimeout, IdleTimeout: gateIdleTimeout}
	go func() { stopped <- server.Serve(listener) }()
	if socksServer != nil {
		go func() { stopped <- socksServer.Serve(ctx, socks) }()
	}
	select {
	case err := <-stopped:
		if ctx.Err() != nil {
			// A front end returning because the gate is being stopped is the
			// normal shutdown, whichever signal was noticed first.
			return shutdown(server)
		}
		// One front end stopping takes the gate down: a half-working gate
		// would fail in confusing ways.
		cancel()
		_ = server.Close()
		if err == nil {
			err = errors.New("app: a gate listener stopped unexpectedly")
		}
		return err
	case <-ctx.Done():
		return shutdown(server)
	}
}

func shutdown(server *http.Server) error {
	shutdownCtx, stop := context.WithTimeout(context.Background(), gateShutdownTimeout)
	defer stop()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return server.Close()
	}
	return nil
}

// Record turns a report into a stored run: it derives the asset graph and the
// blast radius of each finding, summarises the gate's audit log when one is
// given, and saves the result under dataDir. audit may be nil; when it is not,
// only events at or after started are counted, because the gate's log also
// holds earlier runs.
func Record(report Report, cfg config.Config, audit io.Reader, started time.Time, dataDir string, now time.Time) (record.Run, error) {
	st, err := store.Open(dataDir)
	if err != nil {
		return record.Run{}, err
	}
	var events []egress.Event
	if audit != nil {
		if events, err = egress.ReadEvents(audit, started); err != nil {
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
