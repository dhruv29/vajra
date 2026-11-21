package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validMap is a complete configuration as a generic map, so each test can
// change one thing.
func validMap() map[string]any {
	return map[string]any{
		"authorization": map[string]any{"operator": "sec-team@example.test", "statement": "Approved in change CHG-1"},
		"scope":         map[string]any{"hosts": []string{"app.test"}},
		"budget":        map[string]any{"tokens": 100000, "turns": 50, "sandbox_runs": 20, "duration_seconds": 1800},
		"targets":       []string{"https://app.test"},
		"sandbox":       map[string]any{"network": "vajra-task-net", "proxy_url": "http://gate:3128"},
		"nuclei":        map[string]any{"image": "vajra-nuclei:local", "templates_dir": "/opt/nuclei-templates", "timeout_seconds": 900},
	}
}

func encode(t *testing.T, m map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestParseAcceptsAValidConfigAndAppliesDefaults(t *testing.T) {
	c, policy, err := Parse(strings.NewReader(encode(t, validMap())))

	if err != nil {
		t.Fatal(err)
	}
	if policy == nil || policy.CheckTarget("app.test", 443) != nil {
		t.Fatal("the returned policy does not allow the configured host")
	}
	if c.Verify.ReproduceAttempts != 2 || c.Refuter.Provider != RefuterNone || c.Refuter.APIKeyEnv != "ANTHROPIC_API_KEY" {
		t.Fatalf("defaults = %+v, %+v", c.Verify, c.Refuter)
	}
	if c.Authorization.Operator != "sec-team@example.test" || c.Nuclei.TimeoutSeconds != 900 {
		t.Fatalf("config = %+v", c)
	}
}

func TestParseRejectsIncompleteOrUnsafeConfigs(t *testing.T) {
	set := func(section, key string, value any) func(map[string]any) {
		return func(m map[string]any) { m[section].(map[string]any)[key] = value }
	}
	cases := map[string]func(map[string]any){
		"no operator":               set("authorization", "operator", " "),
		"no statement":              set("authorization", "statement", ""),
		"empty scope":               func(m map[string]any) { m["scope"] = map[string]any{} },
		"scope that allows all":     set("scope", "cidrs", []string{"0.0.0.0/0"}),
		"no budget":                 func(m map[string]any) { delete(m, "budget") },
		"unlimited tokens":          set("budget", "tokens", 0),
		"no targets":                func(m map[string]any) { m["targets"] = []string{} },
		"target is not a URL":       func(m map[string]any) { m["targets"] = []string{"app.test"} },
		"target outside scope":      func(m map[string]any) { m["targets"] = []string{"https://other.test"} },
		"target port outside scope": func(m map[string]any) { m["targets"] = []string{"https://app.test:8443"} },
		"no network":                set("sandbox", "network", ""),
		"proxy without a port":      set("sandbox", "proxy_url", "http://gate"),
		"proxy with wrong scheme":   set("sandbox", "proxy_url", "socks5://gate:1080"),
		"no nuclei image":           set("nuclei", "image", ""),
		"no nuclei timeout":         set("nuclei", "timeout_seconds", 0),
		"negative rate limit":       set("nuclei", "rate_limit", -1),
		"too many attempts":         func(m map[string]any) { m["verify"] = map[string]any{"reproduce_attempts": 9} },
		"negative attempts":         func(m map[string]any) { m["verify"] = map[string]any{"reproduce_attempts": -1} },
		"unknown refuter":           func(m map[string]any) { m["refuter"] = map[string]any{"provider": "magic"} },
		"bad topology": func(m map[string]any) {
			m["topology"] = map[string]any{"assets": []map[string]any{{"id": "db", "kind": "spaceship", "name": "x"}}}
		},
		"misspelt field":      func(m map[string]any) { m["scop"] = map[string]any{} },
		"api key in the file": func(m map[string]any) { m["refuter"] = map[string]any{"provider": "anthropic", "api_key": "sk-x"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validMap()
			mutate(m)
			if _, _, err := Parse(strings.NewReader(encode(t, m))); err == nil {
				t.Fatal("Parse succeeded; want an error")
			}
		})
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	for name, input := range map[string]string{
		"not json":      "scope: everything",
		"trailing data": encode(t, validMap()) + ` {"extra": true}`,
		"empty":         "",
	} {
		if _, _, err := Parse(strings.NewReader(input)); err == nil {
			t.Errorf("%s: Parse succeeded", name)
		}
	}
}

func TestLoadReadsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.json")
	m := validMap()
	m["refuter"] = map[string]any{"provider": "anthropic", "model": "claude-sonnet-5-5", "api_key_env": "VAJRA_KEY"}
	if err := os.WriteFile(path, []byte(encode(t, m)), 0o600); err != nil {
		t.Fatal(err)
	}

	c, _, err := Load(path)

	if err != nil || c.Refuter.Provider != RefuterAnthropic || c.Refuter.APIKeyEnv != "VAJRA_KEY" {
		t.Fatalf("config = %+v, err = %v", c.Refuter, err)
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing file was accepted")
	}
}

func sourceSection(root string) map[string]any {
	return map[string]any{
		"root":    root,
		"semgrep": map[string]any{"image": "vajra-semgrep:local", "rules_image_path": "/opt/semgrep-rules", "timeout_seconds": 600},
	}
}

func TestSourceOnlyRunNeedsNoScopeOrScannerSettings(t *testing.T) {
	m := map[string]any{
		"authorization": map[string]any{"operator": "sec@example.test", "statement": "Our own code"},
		"budget":        map[string]any{"tokens": 100000, "turns": 50, "sandbox_runs": 20, "duration_seconds": 1800},
		"source":        sourceSection(t.TempDir()),
	}

	c, policy, err := Parse(strings.NewReader(encode(t, m)))

	if err != nil {
		t.Fatal(err)
	}
	if policy != nil {
		t.Fatal("a code-only run must not get a network policy")
	}
	if c.Source == nil || c.Source.Semgrep.TimeoutSeconds != 600 || len(c.Targets) != 0 {
		t.Fatalf("config = %+v", c)
	}
}

func TestSourceAlongsideTargetsAndLinkedToAService(t *testing.T) {
	m := validMap()
	src := sourceSection(t.TempDir())
	src["serves"] = "https://app.test"
	m["source"] = src

	c, policy, err := Parse(strings.NewReader(encode(t, m)))

	if err != nil || policy == nil || c.Source.Serves != "https://app.test" {
		t.Fatalf("config = %+v, policy = %v, err = %v", c.Source, policy, err)
	}
}

func TestSourceValidation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	semgrep := func(src map[string]any) map[string]any { return src["semgrep"].(map[string]any) }
	cases := map[string]func(src map[string]any){
		"relative root":        func(src map[string]any) { src["root"] = "src" },
		"unclean root":         func(src map[string]any) { src["root"] = dir + "/../x" },
		"missing root":         func(src map[string]any) { src["root"] = filepath.Join(dir, "nope") },
		"root is a file":       func(src map[string]any) { src["root"] = file },
		"serves outside scope": func(src map[string]any) { src["serves"] = "https://other.test" },
		"serves is not a URL":  func(src map[string]any) { src["serves"] = "app.test" },
		"no image":             func(src map[string]any) { semgrep(src)["image"] = "" },
		"no timeout":           func(src map[string]any) { semgrep(src)["timeout_seconds"] = 0 },
		"no rules":             func(src map[string]any) { delete(semgrep(src), "rules_image_path") },
		"both rules":           func(src map[string]any) { semgrep(src)["rules_host_dir"] = "/srv/rules" },
		"relative rules":       func(src map[string]any) { semgrep(src)["rules_image_path"] = "rules" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validMap()
			src := sourceSection(dir)
			mutate(src)
			m["source"] = src
			if _, _, err := Parse(strings.NewReader(encode(t, m))); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestSourceLinkedToAServiceNeedsAScope(t *testing.T) {
	src := sourceSection(t.TempDir())
	src["serves"] = "https://app.test"
	m := map[string]any{
		"authorization": map[string]any{"operator": "sec@example.test", "statement": "Our own code"},
		"budget":        map[string]any{"tokens": 100000, "turns": 50, "sandbox_runs": 20, "duration_seconds": 1800},
		"source":        src,
	}
	if _, _, err := Parse(strings.NewReader(encode(t, m))); err == nil {
		t.Fatal("a service link without a scope was accepted")
	}
}
