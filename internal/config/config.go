// Package config loads and validates a run configuration. A configuration
// that is incomplete or names a target outside its own scope is rejected
// before anything runs.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/topology"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	// RefuterAnthropic reviews findings with a Claude model.
	RefuterAnthropic = "anthropic"
	// RefuterNone skips review; nothing can then be confirmed.
	RefuterNone = "none"

	defaultAPIKeyEnv         = "ANTHROPIC_API_KEY"
	defaultCanaryTemplate    = "/opt/vajra/canary.yaml"
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

// Source describes code to analyse.
type Source struct {
	// Root is the absolute path of the source tree. It is mounted read-only
	// into a container that has no network.
	Root string `json:"root"`
	// Serves is the URL of the running service this code belongs to. It is
	// optional; when set it must be in scope, and it links code findings to
	// the asset graph.
	Serves  string  `json:"serves"`
	Semgrep Semgrep `json:"semgrep"`
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
	return c
}

// needsNetwork reports whether the run names anything reachable, and so needs
// a scope.
func (c Config) needsNetwork() bool {
	return len(c.Targets) > 0 || (c.Source != nil && c.Source.Serves != "")
}

func (c Config) validate() (*scope.Policy, error) {
	if strings.TrimSpace(c.Authorization.Operator) == "" || strings.TrimSpace(c.Authorization.Statement) == "" {
		return nil, errors.New("config: authorization.operator and authorization.statement are required: say who approved this test")
	}
	if len(c.Targets) == 0 && c.Source == nil {
		return nil, errors.New("config: nothing to test: set targets, source, or both")
	}
	if _, err := budget.New(c.Budget, nil); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	// A run that analyses code only touches no network, so it has no scope and
	// gets no policy. Anything that names a host does need one.
	var policy *scope.Policy
	if c.needsNetwork() || len(c.Scope.Hosts)+len(c.Scope.CIDRs) > 0 {
		var err error
		if policy, err = scope.New(c.Scope); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	if len(c.Targets) > 0 {
		if err := c.validateDynamic(policy); err != nil {
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
	if c.Refuter.Provider != RefuterAnthropic && c.Refuter.Provider != RefuterNone {
		return nil, fmt.Errorf("config: refuter.provider %q is not supported", c.Refuter.Provider)
	}
	if err := c.Topology.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return policy, nil
}

func (c Config) validateDynamic(policy *scope.Policy) error {
	if err := checkInScope(policy, "target", c.Targets...); err != nil {
		return err
	}
	if err := c.validateSandbox(); err != nil {
		return err
	}
	if c.Nuclei.Image == "" || c.Nuclei.TemplatesDir == "" || c.Nuclei.TimeoutSeconds <= 0 || c.Nuclei.RateLimit < 0 {
		return errors.New("config: nuclei.image, nuclei.templates_dir and a positive nuclei.timeout_seconds are required")
	}
	return nil
}

func checkInScope(policy *scope.Policy, what string, urls ...string) error {
	for _, raw := range urls {
		host, port, err := verify.TargetHostPort(raw)
		if err != nil {
			return fmt.Errorf("config: %s %q: %w", what, raw, err)
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
	g := s.Semgrep
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
