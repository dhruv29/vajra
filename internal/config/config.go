// Package config loads and validates a run configuration. A configuration
// that is incomplete or names a target outside its own scope is rejected
// before anything runs.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/refute"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/topology"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	// RefuterAnthropic reviews findings with a Claude model.
	RefuterAnthropic = "anthropic"
	// RefuterNone skips review; nothing can then be confirmed.
	RefuterNone = "none"

	defaultAPIKeyEnv      = "ANTHROPIC_API_KEY"
	defaultCanaryTemplate = "/opt/vajra/canary.yaml"
	// UnsafeDeny and UnsafeAsk are the values of agent.unsafe_requests.
	UnsafeDeny = "deny"
	UnsafeAsk  = "ask"

	maxAgentSteps = 200
	maxCrawlPages = 2000
	maxCrawlDepth = 10
	maxReconNames = 5000

	defaultReproduceAttempts = 2
	maxReproduceAttempts     = 5
)

// Authorization records who approved the test. It is copied into every report.
type Authorization struct {
	Operator  string `json:"operator"`
	Statement string `json:"statement"`
}

// Sandbox says where task containers run.
type Sandbox struct {
	// Network is the internal Docker network shared with the egress gate.
	Network string `json:"network"`
	// ProxyURL is the egress gate as seen from that network.
	ProxyURL string `json:"proxy_url"`
	// SocksAddr is the gate's SOCKS5 front end as seen from that network, as
	// host:port. It is needed only for port discovery.
	SocksAddr string `json:"socks_addr"`
}

// GraphQL configures checks on a GraphQL endpoint.
type GraphQL struct {
	Endpoint string `json:"endpoint"`
	// RequiresAuth says the endpoint is expected to refuse anonymous queries.
	RequiresAuth bool `json:"requires_auth"`
}

// Ports configures port discovery: which hosts and ports to try, and which of
// those ports are expected to be open. An open port outside Expected is
// reported. Only ports listed in the scope can be tried at all.
type Ports struct {
	Hosts          []string `json:"hosts"`
	Ports          []int    `json:"ports"`
	Expected       []int    `json:"expected"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

// Nuclei configures the nuclei scanner.
type Nuclei struct {
	Image          string `json:"image"`
	TemplatesDir   string `json:"templates_dir"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	RateLimit      int    `json:"rate_limit"`
	// CanaryTemplate is the path, inside the image, of a template that matches
	// any HTTP response. The image built from deploy/nuclei.Dockerfile has it
	// at the default path.
	CanaryTemplate string `json:"canary_template"`
}

// Semgrep configures the static analyser.
type Semgrep struct {
	Image string `json:"image"`
	// Exactly one of these says where the rules are: a host directory mounted
	// read-only, or a path inside the image.
	RulesHostDir   string `json:"rules_host_dir"`
	RulesImagePath string `json:"rules_image_path"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// Dependencies configures the check of third-party packages.
type Dependencies struct {
	// OSV sends the names and versions of the pinned packages (nothing else)
	// to the public OSV service to look up known vulnerabilities. It is off
	// unless set, because it tells a third party what the project depends on.
	OSV bool `json:"osv"`
}

// Source describes code to analyse. At least one analysis must be enabled.
type Source struct {
	// Root is the absolute path of the source tree. It is mounted read-only
	// into a container that has no network.
	Root string `json:"root"`
	// Serves is the URL of the running service this code belongs to. It is
	// optional; when set it must be in scope, and it links code findings to
	// the asset graph.
	Serves string `json:"serves"`
	// Semgrep enables rule-based code analysis.
	Semgrep *Semgrep `json:"semgrep"`
	// Secrets enables the built-in search for hard-coded credentials.
	Secrets bool `json:"secrets"`
	// Dependencies enables the check of third-party packages.
	Dependencies *Dependencies `json:"dependencies"`
}

// Probe configures Vajra's own HTTP client, which runs in a sandbox behind
// the gate. It is needed by access checks, API tests, crawling and the agent.
type Probe struct {
	// Image must contain the vajra binary as its entrypoint (the image built
	// from the repository's Dockerfile).
	Image          string `json:"image"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	// InsecureTLS accepts any certificate from a target.
	InsecureTLS bool `json:"insecure_tls"`
}

// Identity is a test account. Its credentials are read from environment
// variables at run time and never appear in a configuration file or a report.
type Identity struct {
	Name string `json:"name"`
	// HeadersEnv maps a header name to the environment variable holding its
	// value, for example {"Authorization": "SHOP_ADMIN_TOKEN"}.
	HeadersEnv map[string]string `json:"headers_env"`
}

// AccessCheck states who may get a resource.
type AccessCheck struct {
	Name   string   `json:"name"`
	Method string   `json:"method"`
	URL    string   `json:"url"`
	Allow  []string `json:"allow"`
}

// Auth configures authenticated testing.
type Auth struct {
	Identities []Identity `json:"identities"`
	// ScanAs names the identity whose credentials the scanner, crawler and
	// agent use. Empty means they test anonymously.
	ScanAs       string        `json:"scan_as"`
	AccessChecks []AccessCheck `json:"access_checks"`
}

// Crawl configures link-following discovery from the targets.
type Crawl struct {
	MaxPages int `json:"max_pages"`
	MaxDepth int `json:"max_depth"`
}

// API configures testing against an OpenAPI description.
type API struct {
	// Spec is the path of an OpenAPI 3 JSON file.
	Spec    string            `json:"spec"`
	BaseURL string            `json:"base_url"`
	Params  map[string]string `json:"params"`
}

// Agent configures the autonomous explorer.
type Agent struct {
	MaxSteps int    `json:"max_steps"`
	Goal     string `json:"goal"`
	Model    string `json:"model"`
	// UnsafeRequests says what happens when the agent wants to send a request
	// that could change data: "deny" (the default) or "ask" the operator.
	UnsafeRequests string `json:"unsafe_requests"`
}

// Recon configures discovery of hosts under wildcard scope entries.
type Recon struct {
	MaxNames int      `json:"max_names"`
	Words    []string `json:"words"`
}

// Notify configures the run summary sent to a webhook.
type Notify struct {
	// WebhookURLEnv names the environment variable holding the webhook URL,
	// which usually contains a token.
	WebhookURLEnv string `json:"webhook_url_env"`
	// AllowPrivate permits a webhook on an internal address.
	AllowPrivate bool `json:"allow_private"`
}

// Verify configures the verification pipeline.
type Verify struct {
	ReproduceAttempts int `json:"reproduce_attempts"`
}

// Refuter configures the independent reviewer.
type Refuter struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	// APIKeyEnv names the environment variable that holds the API key. The
	// key itself never appears in a configuration file.
	APIKeyEnv string `json:"api_key_env"`
	// SecondModel, when set, is a different model that must also hold a
	// finding at or above SecondMinSeverity before it is confirmed.
	SecondModel       string `json:"second_model"`
	SecondMinSeverity string `json:"second_min_severity"`
}

// Config is one run's configuration.
type Config struct {
	Authorization Authorization `json:"authorization"`
	Scope         scope.Config  `json:"scope"`
	Budget        budget.Limits `json:"budget"`
	Targets       []string      `json:"targets"`
	// Source is optional. A run needs targets, a source tree, or both.
	Source  *Source `json:"source"`
	Sandbox Sandbox `json:"sandbox"`
	Nuclei  Nuclei  `json:"nuclei"`
	Verify  Verify  `json:"verify"`
	Refuter Refuter `json:"refuter"`
	// Topology is the operator's description of what the targets connect to.
	// It is optional and feeds the blast-radius estimate.
	Topology topology.Declaration `json:"topology"`
	Probe    Probe                `json:"probe"`
	Auth     *Auth                `json:"auth"`
	Crawl    *Crawl               `json:"crawl"`
	API      *API                 `json:"api"`
	Agent    *Agent               `json:"agent"`
	Recon    *Recon               `json:"recon"`
	Notify   *Notify              `json:"notify"`
	GraphQL  *GraphQL             `json:"graphql"`
	Ports    *Ports               `json:"ports"`
}

// Load reads and validates the configuration at path.
func Load(path string) (Config, *scope.Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads and validates a configuration. Unknown fields are an error, so
// a misspelt setting is never silently ignored.
func Parse(r io.Reader) (Config, *scope.Policy, error) {
	var c Config
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, nil, fmt.Errorf("config: %w", err)
	}
	if dec.More() {
		return Config{}, nil, errors.New("config: unexpected data after the configuration object")
	}
	c = c.withDefaults()
	policy, err := c.validate()
	if err != nil {
		return Config{}, nil, err
	}
	return c, policy, nil
}

func (c Config) withDefaults() Config {
	if c.Verify.ReproduceAttempts == 0 {
		c.Verify.ReproduceAttempts = defaultReproduceAttempts
	}
	if c.Refuter.Provider == "" {
		c.Refuter.Provider = RefuterNone
	}
	if c.Refuter.APIKeyEnv == "" {
		c.Refuter.APIKeyEnv = defaultAPIKeyEnv
	}
	if c.Nuclei.CanaryTemplate == "" {
		c.Nuclei.CanaryTemplate = defaultCanaryTemplate
	}
	if c.Refuter.SecondMinSeverity == "" {
		c.Refuter.SecondMinSeverity = string(finding.SeverityHigh)
	}
	if c.Agent != nil && c.Agent.UnsafeRequests == "" {
		agent := *c.Agent
		agent.UnsafeRequests = UnsafeDeny
		c.Agent = &agent
	}
	return c
}

// hasChecks reports whether any access check is configured.
func (c Config) hasChecks() bool { return c.Auth != nil && len(c.Auth.AccessChecks) > 0 }

// IsLive reports whether the run tests anything over the network.
func (c Config) IsLive() bool {
	return len(c.Targets) > 0 || c.hasChecks() || c.API != nil || c.Recon != nil || c.GraphQL != nil || c.Ports != nil
}

// NeedsProbe reports whether the run uses Vajra's own HTTP client.
func (c Config) NeedsProbe() bool {
	return c.hasChecks() || c.API != nil || c.Crawl != nil || c.Agent != nil || c.GraphQL != nil || c.Ports != nil
}

// needsScope reports whether the run names anything reachable.
func (c Config) needsScope() bool {
	return c.IsLive() || (c.Source != nil && c.Source.Serves != "")
}

func (c Config) validate() (*scope.Policy, error) {
	if strings.TrimSpace(c.Authorization.Operator) == "" || strings.TrimSpace(c.Authorization.Statement) == "" {
		return nil, errors.New("config: authorization.operator and authorization.statement are required: say who approved this test")
	}
	if !c.IsLive() && c.Source == nil {
		return nil, errors.New("config: nothing to test: set targets, source, or both")
	}
	if _, err := budget.New(c.Budget, nil); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	// A run that analyses code only touches no network, so it has no scope and
	// gets no policy. Anything that names a host does need one.
	var policy *scope.Policy
	if c.needsScope() || len(c.Scope.Hosts)+len(c.Scope.CIDRs) > 0 {
		var err error
		if policy, err = scope.New(c.Scope); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	checks := []func(*scope.Policy) error{
		c.validateLive, c.validateAuth, c.validateDiscovery, c.validateAPI, c.validateAgent, c.validateRefuter, c.validateNetwork,
	}
	for _, check := range checks {
		if err := check(policy); err != nil {
			return nil, err
		}
	}
	if c.Source != nil {
		if err := c.Source.validate(policy); err != nil {
			return nil, err
		}
	}
	if c.Verify.ReproduceAttempts < 1 || c.Verify.ReproduceAttempts > maxReproduceAttempts {
		return nil, fmt.Errorf("config: verify.reproduce_attempts must be between 1 and %d", maxReproduceAttempts)
	}
	if c.Notify != nil && strings.TrimSpace(c.Notify.WebhookURLEnv) == "" {
		return nil, errors.New("config: notify.webhook_url_env must name the environment variable holding the webhook URL")
	}
	if err := c.Topology.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return policy, nil
}

// validateLive checks what every network-facing run needs.
func (c Config) validateLive(policy *scope.Policy) error {
	// Crawling and exploring start from the targets (or from hosts that
	// discovery adds to them). With neither there is nowhere to begin.
	if len(c.Targets) == 0 && c.Recon == nil && (c.Crawl != nil || c.Agent != nil) {
		return errors.New("config: crawl and agent need targets")
	}
	if !c.IsLive() {
		return nil
	}
	if err := checkInScope(policy, "target", c.Targets...); err != nil {
		return err
	}
	if err := c.validateSandbox(); err != nil {
		return err
	}
	needsScanner := len(c.Targets) > 0 || c.Recon != nil
	if needsScanner && (c.Nuclei.Image == "" || c.Nuclei.TemplatesDir == "" || c.Nuclei.TimeoutSeconds <= 0 || c.Nuclei.RateLimit < 0) {
		return errors.New("config: nuclei.image, nuclei.templates_dir and a positive nuclei.timeout_seconds are required")
	}
	if c.NeedsProbe() && (c.Probe.Image == "" || c.Probe.TimeoutSeconds <= 0) {
		return errors.New("config: probe.image and a positive probe.timeout_seconds are required for access checks, API tests, crawling and the agent")
	}
	return nil
}

var headerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c Config) validateAuth(policy *scope.Policy) error {
	if c.Auth == nil {
		return nil
	}
	names := map[string]bool{}
	for _, id := range c.Auth.Identities {
		if strings.TrimSpace(id.Name) == "" || id.Name == "anonymous" || names[id.Name] {
			return fmt.Errorf("config: auth identity name %q is empty, reserved or repeated", id.Name)
		}
		if len(id.HeadersEnv) == 0 {
			return fmt.Errorf("config: auth identity %q needs headers_env", id.Name)
		}
		for header, env := range id.HeadersEnv {
			if !headerNamePattern.MatchString(header) || !envNamePattern.MatchString(env) {
				return fmt.Errorf("config: auth identity %q: %q -> %q must be a header name and an environment variable name", id.Name, header, env)
			}
		}
		names[id.Name] = true
	}
	if c.Auth.ScanAs != "" && !names[c.Auth.ScanAs] {
		return fmt.Errorf("config: auth.scan_as %q is not a configured identity", c.Auth.ScanAs)
	}
	names["anonymous"] = true
	checkNames := map[string]bool{}
	for _, check := range c.Auth.AccessChecks {
		if strings.TrimSpace(check.Name) == "" || checkNames[check.Name] {
			return fmt.Errorf("config: access check name %q is empty or repeated", check.Name)
		}
		checkNames[check.Name] = true
		// A check is repeated as every account, so only methods that do not
		// change data are allowed.
		switch strings.ToUpper(check.Method) {
		case "", "GET", "HEAD", "OPTIONS":
		default:
			return fmt.Errorf("config: access check %q uses %s; only GET, HEAD and OPTIONS are tested", check.Name, check.Method)
		}
		for _, allowed := range check.Allow {
			if !names[allowed] {
				return fmt.Errorf("config: access check %q allows unknown identity %q", check.Name, allowed)
			}
		}
		if err := checkInScope(policy, "access check "+check.Name, check.URL); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateDiscovery(policy *scope.Policy) error {
	if c.Crawl != nil && (c.Crawl.MaxPages < 1 || c.Crawl.MaxPages > maxCrawlPages || c.Crawl.MaxDepth < 0 || c.Crawl.MaxDepth > maxCrawlDepth) {
		return fmt.Errorf("config: crawl.max_pages must be 1-%d and crawl.max_depth 0-%d", maxCrawlPages, maxCrawlDepth)
	}
	if c.Recon == nil {
		return nil
	}
	if c.Recon.MaxNames < 1 || c.Recon.MaxNames > maxReconNames {
		return fmt.Errorf("config: recon.max_names must be 1-%d", maxReconNames)
	}
	if policy == nil || len(policy.WildcardBases()) == 0 {
		return errors.New("config: recon looks under wildcard scope entries such as *.example.com, and there are none")
	}
	return nil
}

func (c Config) validateAPI(policy *scope.Policy) error {
	if c.API == nil {
		return nil
	}
	if !filepath.IsAbs(c.API.Spec) {
		return fmt.Errorf("config: api.spec %q must be an absolute path to an OpenAPI JSON file", c.API.Spec)
	}
	return checkInScope(policy, "api.base_url", c.API.BaseURL)
}

// validateNetwork checks the GraphQL and port-discovery sections.
func (c Config) validateNetwork(policy *scope.Policy) error {
	if c.GraphQL != nil {
		if err := checkInScope(policy, "graphql.endpoint", c.GraphQL.Endpoint); err != nil {
			return err
		}
	}
	if c.Ports == nil {
		return nil
	}
	p := c.Ports
	if len(p.Hosts) == 0 || len(p.Ports) == 0 || p.TimeoutSeconds <= 0 {
		return errors.New("config: ports needs hosts, ports and a positive timeout_seconds")
	}
	if _, _, err := net.SplitHostPort(c.Sandbox.SocksAddr); err != nil {
		return fmt.Errorf("config: ports needs sandbox.socks_addr as host:port, the gate's SOCKS5 address on the task network")
	}
	for _, host := range p.Hosts {
		for _, port := range p.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("config: ports: %d is not a port", port)
			}
			if err := policy.CheckTarget(host, uint16(port)); err != nil {
				return fmt.Errorf("config: ports: %s:%d is outside the configured scope, so the gate would refuse it: %w", host, port, err)
			}
		}
	}
	return nil
}

func (c Config) validateAgent(*scope.Policy) error {
	if c.Agent == nil {
		return nil
	}
	if c.Agent.MaxSteps < 1 || c.Agent.MaxSteps > maxAgentSteps {
		return fmt.Errorf("config: agent.max_steps must be 1-%d", maxAgentSteps)
	}
	if c.Agent.UnsafeRequests != UnsafeDeny && c.Agent.UnsafeRequests != UnsafeAsk {
		return fmt.Errorf("config: agent.unsafe_requests must be %q or %q", UnsafeDeny, UnsafeAsk)
	}
	if c.Refuter.Provider != RefuterAnthropic {
		return errors.New("config: the agent needs refuter.provider \"anthropic\": it uses the same API key, and its reports must be reviewed")
	}
	return nil
}

func (c Config) validateRefuter(*scope.Policy) error {
	if c.Refuter.Provider != RefuterAnthropic && c.Refuter.Provider != RefuterNone {
		return fmt.Errorf("config: refuter.provider %q is not supported", c.Refuter.Provider)
	}
	if finding.ParseSeverity(c.Refuter.SecondMinSeverity) == finding.SeverityUnknown {
		return fmt.Errorf("config: refuter.second_min_severity %q is not a severity", c.Refuter.SecondMinSeverity)
	}
	if c.Refuter.SecondModel == "" {
		return nil
	}
	if c.Refuter.Provider != RefuterAnthropic {
		return errors.New("config: refuter.second_model needs refuter.provider \"anthropic\"")
	}
	// An unset model means the default, so compare with what will really run.
	first := c.Refuter.Model
	if first == "" {
		first = refute.DefaultModel
	}
	if c.Refuter.SecondModel == first {
		return errors.New("config: refuter.second_model must differ from refuter.model, or it adds nothing")
	}
	return nil
}

func checkInScope(policy *scope.Policy, what string, urls ...string) error {
	for _, raw := range urls {
		host, port, err := verify.TargetHostPort(raw)
		if err != nil {
			return fmt.Errorf("config: %s %q: %w", what, raw, err)
		}
		if policy == nil {
			return fmt.Errorf("config: %s %q needs a scope", what, raw)
		}
		if err := policy.CheckTarget(host, port); err != nil {
			return fmt.Errorf("config: %s %q is outside the configured scope: %w", what, raw, err)
		}
	}
	return nil
}

func (s Source) validate(policy *scope.Policy) error {
	if !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return fmt.Errorf("config: source.root %q must be a clean absolute path", s.Root)
	}
	info, err := os.Stat(s.Root)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("config: source.root %q is not a readable directory", s.Root)
	}
	if s.Serves != "" {
		if err := checkInScope(policy, "source.serves", s.Serves); err != nil {
			return err
		}
	}
	if s.Semgrep == nil && !s.Secrets && (s.Dependencies == nil || !s.Dependencies.OSV) {
		return errors.New("config: source enables no analysis: set source.semgrep, source.secrets or source.dependencies")
	}
	if s.Semgrep == nil {
		return nil
	}
	g := *s.Semgrep
	if g.Image == "" || g.TimeoutSeconds <= 0 {
		return errors.New("config: source.semgrep.image and a positive source.semgrep.timeout_seconds are required")
	}
	if (g.RulesHostDir == "") == (g.RulesImagePath == "") {
		return errors.New("config: set exactly one of source.semgrep.rules_host_dir and source.semgrep.rules_image_path")
	}
	for name, path := range map[string]string{"rules_host_dir": g.RulesHostDir, "rules_image_path": g.RulesImagePath} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return fmt.Errorf("config: source.semgrep.%s %q must be a clean absolute path", name, path)
		}
	}
	return nil
}

func (c Config) validateSandbox() error {
	if c.Sandbox.Network == "" {
		return errors.New("config: sandbox.network is required")
	}
	u, err := url.Parse(c.Sandbox.ProxyURL)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.Port() == "" {
		return fmt.Errorf("config: sandbox.proxy_url %q must look like http://host:port", c.Sandbox.ProxyURL)
	}
	return nil
}
