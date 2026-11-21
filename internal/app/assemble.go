package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/dhruv29/vajra/internal/access"
	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/apitest"
	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/llm"
	"github.com/dhruv29/vajra/internal/nuclei"
	"github.com/dhruv29/vajra/internal/openapi"
	"github.com/dhruv29/vajra/internal/osv"
	"github.com/dhruv29/vajra/internal/probe"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/refute"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/secrets"
	"github.com/dhruv29/vajra/internal/semgrep"
	"github.com/dhruv29/vajra/internal/verify"
)

// staticReproduceAttempts is one because static analysis is deterministic:
// the same code and rules give the same answer every time.
const staticReproduceAttempts = 1

// run holds the assembled parts of one run. A part is nil when the
// configuration does not enable it.
type run struct {
	cfg    config.Config
	deps   Deps
	policy *scope.Policy
	budget *budget.Budget

	// targets starts as the configured list and grows with discovered hosts.
	targets  []string
	activity record.Activity
	// identities are the test accounts with their credentials resolved.
	identities []access.Identity
	// scanHeaders are the credentials of the account the scanner uses.
	scanHeaders   map[string]string
	secretHeaders []string

	fetcher  probe.Fetcher
	nuclei   *nuclei.Scanner
	checker  *access.Checker
	api      *apitest.Tester
	explorer *agent.Explorer
	semgrep  *semgrep.Scanner
	osv      *osvReproducer
	model    llm.Sender

	dynamicPipeline    *verify.Pipeline
	staticPipeline     *verify.Pipeline
	dependencyPipeline *verify.Pipeline
}

func assemble(cfg config.Config, policy *scope.Policy, deps Deps) (*run, error) {
	if deps.Runner == nil || deps.Getenv == nil {
		return nil, errors.New("app: a sandbox runner and an environment lookup are required")
	}
	deps = withDefaults(deps)
	b, err := budget.New(cfg.Budget, deps.Now)
	if err != nil {
		return nil, err
	}
	// Every sandbox run is charged to the budget and cut off at the run's
	// remaining time, wherever in the code it is started.
	deps.Runner = budgetRunner{inner: deps.Runner, budget: b}
	r := &run{cfg: cfg, deps: deps, policy: policy, budget: b, targets: append([]string{}, cfg.Targets...)}
	refuteStage, err := r.refuteStage()
	if err != nil {
		return nil, err
	}
	if cfg.IsLive() {
		if err := r.addLive(refuteStage); err != nil {
			return nil, err
		}
	}
	if cfg.Source != nil {
		if err := r.addSource(refuteStage); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func withDefaults(deps Deps) Deps {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Resolver == nil {
		deps.Resolver = net.DefaultResolver
	}
	if deps.Approve == nil {
		deps.Approve = agent.DenyAll
	}
	if deps.ReadFile == nil {
		deps.ReadFile = os.ReadFile
	}
	return deps
}

// budgetRunner charges every sandbox run to the budget, refuses one when the
// budget is spent, and shortens its timeout to the time that is left.
type budgetRunner struct {
	inner  sandbox.Runner
	budget *budget.Budget
}

func (b budgetRunner) Run(ctx context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	if err := b.budget.SpendRun(); err != nil {
		return sandbox.Result{}, err
	}
	if left := b.budget.Remaining(); spec.Timeout > left {
		spec.Timeout = left
	}
	return b.inner.Run(ctx, spec)
}

// refuteStage builds the review stage: one reviewer, or two for serious
// findings when a second model is configured.
func (r *run) refuteStage() (verify.RefuteStage, error) {
	cfg := r.cfg.Refuter
	if cfg.Provider == config.RefuterNone {
		// No model call is made, so no turn is charged.
		return verify.RefuteStage{Refuter: refute.None{}}, nil
	}
	key := r.deps.Getenv(cfg.APIKeyEnv)
	if key == "" {
		return verify.RefuteStage{}, fmt.Errorf("app: the refuter needs an API key in the %s environment variable", cfg.APIKeyEnv)
	}
	newReviewer := func(model string) (verify.Refuter, error) {
		return refute.NewAnthropic(refute.Options{
			APIKey: key, Model: model, BaseURL: r.deps.ModelBaseURL, Client: r.deps.ModelClient, Budget: r.budget,
		})
	}
	reviewer, err := newReviewer(cfg.Model)
	if err != nil {
		return verify.RefuteStage{}, err
	}
	if cfg.SecondModel != "" {
		second, err := newReviewer(cfg.SecondModel)
		if err != nil {
			return verify.RefuteStage{}, err
		}
		reviewer = refute.Panel{
			Primary: reviewer, Second: second, MinSeverity: finding.ParseSeverity(cfg.SecondMinSeverity), Budget: r.budget,
		}
	}
	agentModel := ""
	if r.cfg.Agent != nil {
		agentModel = r.cfg.Agent.Model
	}
	r.model, err = llm.NewClient(llm.Options{APIKey: key, Model: agentModel, BaseURL: r.deps.ModelBaseURL, HTTP: r.deps.ModelClient})
	if err != nil {
		return verify.RefuteStage{}, err
	}
	return verify.RefuteStage{Refuter: reviewer, Budget: r.budget}, nil
}

// preflight checks, before anything is sent, that the task network really is
// closed off.
func (r *run) preflight(ctx context.Context) error {
	if !r.cfg.IsLive() {
		return nil
	}
	return r.deps.CheckNetwork(ctx, r.cfg.Sandbox.Network)
}

// addLive prepares everything that tests over the network.
func (r *run) addLive(refuteStage verify.RefuteStage) error {
	if r.policy == nil {
		return errors.New("app: testing over the network needs a scope")
	}
	if r.deps.CheckNetwork == nil {
		return errors.New("app: a task-network check is required when anything is tested over the network")
	}
	if err := r.resolveIdentities(); err != nil {
		return err
	}
	cfg := r.cfg
	router := verify.SourceRouter{}
	if len(cfg.Targets) > 0 || cfg.Recon != nil {
		r.nuclei = &nuclei.Scanner{
			Runner: r.deps.Runner, Image: cfg.Nuclei.Image, TemplatesDir: cfg.Nuclei.TemplatesDir,
			Network: cfg.Sandbox.Network, ProxyURL: cfg.Sandbox.ProxyURL,
			Timeout: time.Duration(cfg.Nuclei.TimeoutSeconds) * time.Second, RateLimit: cfg.Nuclei.RateLimit,
			CanaryTemplate: cfg.Nuclei.CanaryTemplate, Headers: r.scanHeaders,
		}
		if err := r.nuclei.Validate(); err != nil {
			return err
		}
		router[nuclei.Source] = r.nuclei
	}
	if cfg.NeedsProbe() {
		if err := r.addProbeUsers(router); err != nil {
			return err
		}
	}
	var err error
	r.dynamicPipeline, err = verify.NewPipeline(r.deps.Now,
		verify.EvidenceStage{},
		verify.ScopeStage{Policy: r.policy},
		verify.ReproduceStage{Reproducer: router, Attempts: cfg.Verify.ReproduceAttempts},
		refuteStage,
	)
	return err
}

// resolveIdentities reads each test account's credentials from the
// environment. A missing variable is an error: testing as "admin" with no
// credentials would silently test as nobody.
func (r *run) resolveIdentities() error {
	if r.cfg.Auth == nil {
		return nil
	}
	secret := map[string]bool{}
	for _, id := range r.cfg.Auth.Identities {
		headers := map[string]string{}
		for header, env := range id.HeadersEnv {
			value := r.deps.Getenv(env)
			if value == "" {
				return fmt.Errorf("app: identity %q needs the %s environment variable", id.Name, env)
			}
			headers[header] = value
			secret[header] = true
		}
		r.identities = append(r.identities, access.Identity{Name: id.Name, Headers: headers})
		if id.Name == r.cfg.Auth.ScanAs {
			r.scanHeaders = headers
		}
	}
	for header := range secret {
		r.secretHeaders = append(r.secretHeaders, header)
	}
	return nil
}

// addProbeUsers prepares the parts that use Vajra's own HTTP client.
func (r *run) addProbeUsers(router verify.SourceRouter) error {
	cfg := r.cfg
	runner := &probe.Runner{
		Sandbox: r.deps.Runner, Image: cfg.Probe.Image, Network: cfg.Sandbox.Network, ProxyURL: cfg.Sandbox.ProxyURL,
		Timeout: time.Duration(cfg.Probe.TimeoutSeconds) * time.Second, InsecureTLS: cfg.Probe.InsecureTLS,
	}
	if err := runner.Validate(); err != nil {
		return err
	}
	r.fetcher = runner
	if cfg.Auth != nil && len(cfg.Auth.AccessChecks) > 0 {
		checks := make([]access.Check, 0, len(cfg.Auth.AccessChecks))
		for _, c := range cfg.Auth.AccessChecks {
			checks = append(checks, access.Check{Name: c.Name, Method: c.Method, URL: c.URL, Allow: c.Allow})
		}
		var err error
		if r.checker, err = access.NewChecker(r.fetcher, r.identities, checks); err != nil {
			return err
		}
		router[access.Source] = r.checker
	}
	if cfg.API != nil {
		if err := r.addAPI(router); err != nil {
			return err
		}
	}
	if cfg.Agent != nil {
		// The explorer is created when it runs, because its briefing depends
		// on what the earlier stages found. Its reports are re-tested by it.
		router[agent.Source] = verify.Reproducer(lateReproducer{get: func() verify.Reproducer {
			if r.explorer == nil {
				return nil
			}
			return r.explorer
		}})
	}
	return nil
}

func (r *run) addAPI(router verify.SourceRouter) error {
	raw, err := r.deps.ReadFile(r.cfg.API.Spec)
	if err != nil {
		return fmt.Errorf("app: read the API description: %w", err)
	}
	doc, err := openapi.Parse(bytesReader(raw))
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}
	if r.api, err = apitest.New(r.fetcher, doc, r.cfg.API.BaseURL, r.cfg.API.Params); err != nil {
		return err
	}
	router[apitest.Source] = r.api
	return nil
}

// lateReproducer forwards to a reproducer that does not exist yet when the
// pipeline is built.
type lateReproducer struct {
	get func() verify.Reproducer
}

func (l lateReproducer) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	reproducer := l.get()
	if reproducer == nil {
		return false, errors.New("the exploration that reported this finding is not available to re-test it")
	}
	return reproducer.Reproduce(ctx, f)
}

// addSource prepares the analyses of the source tree.
func (r *run) addSource(refuteStage verify.RefuteStage) error {
	src := r.cfg.Source
	router := verify.SourceRouter{}
	if src.Semgrep != nil {
		r.semgrep = &semgrep.Scanner{
			Runner: r.deps.Runner, Image: src.Semgrep.Image, SourceRoot: src.Root,
			RulesHostDir: src.Semgrep.RulesHostDir, RulesImagePath: src.Semgrep.RulesImagePath,
			AssetURL: src.Serves, Timeout: time.Duration(src.Semgrep.TimeoutSeconds) * time.Second,
		}
		if err := r.semgrep.Validate(); err != nil {
			return err
		}
		router[semgrep.Source] = r.semgrep
	}
	if src.Secrets {
		router[secrets.Source] = secretsReproducer{root: src.Root}
	}
	var err error
	r.staticPipeline, err = verify.NewPipeline(r.deps.Now,
		verify.CodeEvidenceStage{},
		verify.SourceScopeStage{},
		verify.ReproduceStage{Reproducer: router, Attempts: staticReproduceAttempts},
		refuteStage,
	)
	if err != nil {
		return err
	}
	if src.Dependencies != nil && src.Dependencies.OSV {
		r.osv = &osvReproducer{
			client:   osv.NewClient(osv.Options{BaseURL: r.deps.OSVBaseURL, HTTP: r.deps.ModelClient}),
			packages: map[string]osv.Package{},
		}
		// A dependency finding states a fact: this version is pinned and this
		// advisory covers it. Looking it up again is the whole check, so there
		// is no review stage; whether the flaw is reachable is not claimed.
		r.dependencyPipeline, err = verify.NewPipeline(r.deps.Now,
			verify.PackageEvidenceStage{},
			verify.ReproduceStage{Reproducer: r.osv, Attempts: staticReproduceAttempts},
		)
	}
	return err
}

// secretsReproducer re-scans one file for a hard-coded credential.
type secretsReproducer struct {
	root string
}

func (s secretsReproducer) Reproduce(_ context.Context, f finding.Finding) (bool, error) {
	return secrets.Reproduce(s.root, f)
}

// osvReproducer looks one package up again.
type osvReproducer struct {
	client   *osv.Client
	packages map[string]osv.Package
}

func (o *osvReproducer) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	if len(f.Evidence.Extracted) == 0 {
		return false, errors.New("the finding does not name a package")
	}
	pkg, ok := o.packages[f.Evidence.Extracted[0]]
	if !ok {
		return false, errors.New("the package is not in this run's inventory")
	}
	advisories, err := o.client.Query(ctx, []osv.Package{pkg})
	if err != nil {
		return false, err
	}
	for _, advisory := range advisories[0] {
		if advisory.ID == f.RuleID {
			return true, nil
		}
	}
	return false, nil
}
