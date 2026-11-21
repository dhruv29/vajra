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
	"strings"

	"github.com/dhruv29/vajra/internal/budget"
	"github.com/dhruv29/vajra/internal/scope"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	// RefuterAnthropic reviews findings with a Claude model.
	RefuterAnthropic = "anthropic"
	// RefuterNone skips review; nothing can then be confirmed.
	RefuterNone = "none"

	defaultAPIKeyEnv         = "ANTHROPIC_API_KEY"
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
	Sandbox       Sandbox       `json:"sandbox"`
	Nuclei        Nuclei        `json:"nuclei"`
	Verify        Verify        `json:"verify"`
	Refuter       Refuter       `json:"refuter"`
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
	return c
}

func (c Config) validate() (*scope.Policy, error) {
	if strings.TrimSpace(c.Authorization.Operator) == "" || strings.TrimSpace(c.Authorization.Statement) == "" {
		return nil, errors.New("config: authorization.operator and authorization.statement are required: say who approved this test")
	}
	policy, err := scope.New(c.Scope)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := budget.New(c.Budget, nil); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.validateTargets(policy); err != nil {
		return nil, err
	}
	if err := c.validateSandbox(); err != nil {
		return nil, err
	}
	if c.Nuclei.Image == "" || c.Nuclei.TemplatesDir == "" || c.Nuclei.TimeoutSeconds <= 0 || c.Nuclei.RateLimit < 0 {
		return nil, errors.New("config: nuclei.image, nuclei.templates_dir and a positive nuclei.timeout_seconds are required")
	}
	if c.Verify.ReproduceAttempts < 1 || c.Verify.ReproduceAttempts > maxReproduceAttempts {
		return nil, fmt.Errorf("config: verify.reproduce_attempts must be between 1 and %d", maxReproduceAttempts)
	}
	if c.Refuter.Provider != RefuterAnthropic && c.Refuter.Provider != RefuterNone {
		return nil, fmt.Errorf("config: refuter.provider %q is not supported", c.Refuter.Provider)
	}
	return policy, nil
}

func (c Config) validateTargets(policy *scope.Policy) error {
	if len(c.Targets) == 0 {
		return errors.New("config: at least one target is required")
	}
	for _, target := range c.Targets {
		host, port, err := verify.TargetHostPort(target)
		if err != nil {
			return fmt.Errorf("config: target %q: %w", target, err)
		}
		if err := policy.CheckTarget(host, port); err != nil {
			return fmt.Errorf("config: target %q is outside the configured scope: %w", target, err)
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
