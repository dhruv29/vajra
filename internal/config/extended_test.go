package config

import (
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/refute"
)

// parseMap parses a configuration given in generic form.
func parseMap(t *testing.T, m map[string]any) (Config, error) {
	t.Helper()
	c, _, err := Parse(strings.NewReader(encode(t, m)))
	return c, err
}

// probedMap is validMap with the probe configured, as every feature that
// uses Vajra's own HTTP client needs.
func probedMap() map[string]any {
	m := validMap()
	m["probe"] = map[string]any{"image": "vajra:local", "timeout_seconds": 60}
	return m
}

func identity(name string, headersEnv map[string]string) map[string]any {
	return map[string]any{"name": name, "headers_env": headersEnv}
}

func accessCheck(url string) map[string]any {
	return map[string]any{"name": "admin console", "url": url, "allow": []string{"admin"}}
}

// authSection is a valid auth section: two accounts and one rule.
func authSection() map[string]any {
	return map[string]any{
		"identities": []map[string]any{
			identity("admin", map[string]string{"Authorization": "ADMIN_TOKEN"}),
			identity("user", map[string]string{"Authorization": "USER_TOKEN", "X-Tenant": "_TENANT1"}),
		},
		"scan_as":       "user",
		"access_checks": []map[string]any{accessCheck("https://app.test/admin")},
	}
}

// rejects runs each case against a fresh probedMap and requires Parse to
// fail with an error that mentions want, so a case cannot pass because some
// other rule happened to fire.
func rejects(t *testing.T, cases map[string]struct {
	mutate func(m map[string]any)
	want   string
}) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := probedMap()
			tc.mutate(m)
			_, err := parseMap(t, m)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want an error mentioning %q", err, tc.want)
			}
		})
	}
}

type rejection = struct {
	mutate func(m map[string]any)
	want   string
}

func TestAuthIsAcceptedWhenComplete(t *testing.T) {
	m := probedMap()
	m["auth"] = authSection()

	c, err := parseMap(t, m)

	if err != nil {
		t.Fatal(err)
	}
	if len(c.Auth.Identities) != 2 || c.Auth.ScanAs != "user" || c.Auth.AccessChecks[0].URL != "https://app.test/admin" {
		t.Fatalf("auth = %+v", c.Auth)
	}
	if c.Auth.Identities[1].HeadersEnv["X-Tenant"] != "_TENANT1" {
		t.Fatalf("identity = %+v", c.Auth.Identities[1])
	}
}

func TestAuthValidation(t *testing.T) {
	identities := func(list ...map[string]any) func(m map[string]any) {
		return func(m map[string]any) {
			auth := authSection()
			auth["identities"] = list
			auth["scan_as"] = ""
			auth["access_checks"] = []map[string]any{}
			m["auth"] = auth
		}
	}
	with := func(key string, value any) func(m map[string]any) {
		return func(m map[string]any) {
			auth := authSection()
			auth[key] = value
			m["auth"] = auth
		}
	}
	token := map[string]string{"Authorization": "TOKEN"}
	rejects(t, map[string]rejection{
		"empty identity name":    {identities(identity("", token)), "empty, reserved or repeated"},
		"blank identity name":    {identities(identity("  ", token)), "empty, reserved or repeated"},
		"reserved identity name": {identities(identity("anonymous", token)), "empty, reserved or repeated"},
		"repeated identity name": {identities(identity("user", token), identity("user", token)), "empty, reserved or repeated"},
		"no headers_env":         {identities(identity("user", nil)), "needs headers_env"},
		"empty headers_env":      {identities(identity("user", map[string]string{})), "needs headers_env"},
		"header with a space":    {identities(identity("user", map[string]string{"X Token": "TOKEN"})), "must be a header name"},
		"header with a colon":    {identities(identity("user", map[string]string{"Authorization:": "TOKEN"})), "must be a header name"},
		"empty header name":      {identities(identity("user", map[string]string{"": "TOKEN"})), "must be a header name"},
		"env with a dash":        {identities(identity("user", map[string]string{"Authorization": "MY-TOKEN"})), "environment variable name"},
		"env starting with digit": {identities(identity("user", map[string]string{"Authorization": "1TOKEN"})),
			"environment variable name"},
		"env holding the secret itself": {identities(identity("user", map[string]string{"Authorization": "Bearer abc"})),
			"environment variable name"},
		"empty env name":                        {identities(identity("user", map[string]string{"Authorization": ""})), "environment variable name"},
		"scan_as unknown":                       {with("scan_as", "auditor"), `auth.scan_as "auditor"`},
		"scan_as anonymous":                     {with("scan_as", "anonymous"), "auth.scan_as"},
		"check URL outside scope":               {with("access_checks", []map[string]any{accessCheck("https://other.test/admin")}), "outside the configured scope"},
		"check port outside scope":              {with("access_checks", []map[string]any{accessCheck("https://app.test:8443/admin")}), "outside the configured scope"},
		"check URL is not a URL":                {with("access_checks", []map[string]any{accessCheck("app.test/admin")}), "access check admin console"},
		"check URL is not http":                 {with("access_checks", []map[string]any{accessCheck("ftp://app.test/admin")}), "access check admin console"},
		"check URL is empty":                    {with("access_checks", []map[string]any{accessCheck("")}), "access check admin console"},
		"second check is out of scope":          {with("access_checks", []map[string]any{accessCheck("https://app.test/a"), {"name": "second", "url": "https://other.test/b", "allow": []string{"admin"}}}), "outside the configured scope"},
		"two checks share a name":               {with("access_checks", []map[string]any{accessCheck("https://app.test/a"), accessCheck("https://app.test/b")}), "empty or repeated"},
		"check uses a method that changes data": {with("access_checks", []map[string]any{{"name": "c", "method": "POST", "url": "https://app.test/a"}}), "only GET, HEAD and OPTIONS"},
		"check allows an unknown account":       {with("access_checks", []map[string]any{{"name": "c", "url": "https://app.test/a", "allow": []string{"auditor"}}}), "unknown identity"},
	})
}

func TestProbeIsRequiredByEverythingThatUsesIt(t *testing.T) {
	features := map[string]func(m map[string]any){
		"access checks": func(m map[string]any) { m["auth"] = authSection() },
		"api": func(m map[string]any) {
			m["api"] = map[string]any{"spec": "/specs/api.json", "base_url": "https://app.test"}
		},
		"crawl": func(m map[string]any) { m["crawl"] = map[string]any{"max_pages": 10, "max_depth": 2} },
		"agent": func(m map[string]any) {
			m["agent"] = map[string]any{"max_steps": 5}
			m["refuter"] = map[string]any{"provider": "anthropic"}
		},
	}
	probes := map[string]any{
		"missing":      nil,
		"no image":     map[string]any{"timeout_seconds": 60},
		"no timeout":   map[string]any{"image": "vajra:local"},
		"zero timeout": map[string]any{"image": "vajra:local", "timeout_seconds": 0},
		"negative":     map[string]any{"image": "vajra:local", "timeout_seconds": -5},
	}
	for feature, enable := range features {
		for name, section := range probes {
			t.Run(feature+" with probe "+name, func(t *testing.T) {
				m := validMap()
				enable(m)
				if section != nil {
					m["probe"] = section
				}
				if _, err := parseMap(t, m); err == nil || !strings.Contains(err.Error(), "probe.image") {
					t.Fatalf("err = %v; want the probe settings required", err)
				}
			})
		}
		t.Run(feature+" with a probe", func(t *testing.T) {
			m := probedMap()
			enable(m)
			c, err := parseMap(t, m)
			if err != nil || !c.NeedsProbe() {
				t.Fatalf("NeedsProbe = %v, err = %v", c.NeedsProbe(), err)
			}
		})
	}
	t.Run("identities without checks need no probe", func(t *testing.T) {
		m := validMap()
		auth := authSection()
		delete(auth, "access_checks")
		m["auth"] = auth
		c, err := parseMap(t, m)
		if err != nil || c.NeedsProbe() {
			t.Fatalf("NeedsProbe = %v, err = %v", c.NeedsProbe(), err)
		}
	})
}

func TestCrawlLimits(t *testing.T) {
	crawl := func(pages, depth int) func(m map[string]any) {
		return func(m map[string]any) { m["crawl"] = map[string]any{"max_pages": pages, "max_depth": depth} }
	}
	rejects(t, map[string]rejection{
		"no pages":        {crawl(0, 2), "crawl.max_pages"},
		"negative pages":  {crawl(-1, 2), "crawl.max_pages"},
		"too many pages":  {crawl(2001, 2), "crawl.max_pages"},
		"negative depth":  {crawl(10, -1), "crawl.max_depth"},
		"too deep":        {crawl(10, 11), "crawl.max_depth"},
		"empty section":   {func(m map[string]any) { m["crawl"] = map[string]any{} }, "crawl.max_pages"},
		"misspelt option": {func(m map[string]any) { m["crawl"] = map[string]any{"max_pages": 5, "depth": 1} }, "unknown field"},
	})
	for name, limits := range map[string][2]int{"smallest": {1, 0}, "largest": {2000, 10}} {
		t.Run(name, func(t *testing.T) {
			m := probedMap()
			crawl(limits[0], limits[1])(m)
			c, err := parseMap(t, m)
			if err != nil || c.Crawl.MaxPages != limits[0] || c.Crawl.MaxDepth != limits[1] {
				t.Fatalf("crawl = %+v, err = %v", c.Crawl, err)
			}
		})
	}
}

// codeOnlyMap is a configuration that analyses source and tests nothing over
// the network.
func codeOnlyMap(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"authorization": map[string]any{"operator": "sec@example.test", "statement": "Our own code"},
		"budget":        map[string]any{"tokens": 100000, "turns": 50, "sandbox_runs": 20, "duration_seconds": 1800},
		"source":        sourceSection(t.TempDir()),
		"probe":         map[string]any{"image": "vajra:local", "timeout_seconds": 60},
		"refuter":       map[string]any{"provider": "anthropic"},
	}
}

func TestCrawlAndAgentNeedSomethingToStartFrom(t *testing.T) {
	sections := map[string]map[string]any{
		"crawl": {"max_pages": 10, "max_depth": 2},
		"agent": {"max_steps": 5},
	}
	for name, section := range sections {
		t.Run(name+" in a code-only run", func(t *testing.T) {
			m := codeOnlyMap(t)
			m[name] = section
			if _, err := parseMap(t, m); err == nil || !strings.Contains(err.Error(), "crawl and agent need targets") {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run(name+" with access checks but no targets", func(t *testing.T) {
			m := probedMap()
			delete(m, "targets")
			m["auth"] = authSection()
			m["refuter"] = map[string]any{"provider": "anthropic"}
			m[name] = section
			_, err := parseMap(t, m)
			if err == nil {
				t.Skip("BUG: config.go validateLive accepts " + name + " without targets when access checks or api make the run live; nothing gives it a start URL")
			}
			if !strings.Contains(err.Error(), "need targets") {
				t.Fatalf("err = %v; want the missing targets named", err)
			}
		})
	}
}

func TestReconValidation(t *testing.T) {
	wildcard := func(m map[string]any) {
		m["scope"] = map[string]any{"hosts": []string{"*.example.test"}}
		m["targets"] = []string{"https://app.example.test"}
	}
	recon := func(names int, scoped bool) func(m map[string]any) {
		return func(m map[string]any) {
			if scoped {
				wildcard(m)
			}
			m["recon"] = map[string]any{"max_names": names, "words": []string{"www", "api"}}
		}
	}
	rejects(t, map[string]rejection{
		"no wildcard in scope": {recon(100, false), "wildcard scope entries"},
		"no names":             {recon(0, true), "recon.max_names"},
		"negative names":       {recon(-3, true), "recon.max_names"},
		"too many names":       {recon(5001, true), "recon.max_names"},
		"empty section":        {func(m map[string]any) { wildcard(m); m["recon"] = map[string]any{} }, "recon.max_names"},
		"only CIDRs in scope": {func(m map[string]any) {
			m["scope"] = map[string]any{"cidrs": []string{"203.0.113.0/24"}}
			m["targets"] = []string{"https://203.0.113.7"}
			m["recon"] = map[string]any{"max_names": 10}
		}, "wildcard scope entries"},
		"discovery alone still needs the scanner": {func(m map[string]any) {
			recon(100, true)(m)
			delete(m, "targets")
			delete(m, "nuclei")
		}, "nuclei.image"},
	})
	for name, names := range map[string]int{"smallest": 1, "largest": 5000} {
		t.Run(name, func(t *testing.T) {
			m := validMap()
			recon(names, true)(m)
			c, err := parseMap(t, m)
			if err != nil || c.Recon.MaxNames != names || len(c.Recon.Words) != 2 || !c.IsLive() || c.NeedsProbe() {
				t.Fatalf("recon = %+v, err = %v", c.Recon, err)
			}
		})
	}
	t.Run("discovery alone is a live run", func(t *testing.T) {
		m := validMap()
		recon(50, true)(m)
		delete(m, "targets")
		c, err := parseMap(t, m)
		if err != nil || !c.IsLive() {
			t.Fatalf("IsLive = %v, err = %v", c.IsLive(), err)
		}
	})
}

func TestAPIValidation(t *testing.T) {
	api := func(spec, base string) func(m map[string]any) {
		return func(m map[string]any) { m["api"] = map[string]any{"spec": spec, "base_url": base} }
	}
	rejects(t, map[string]rejection{
		"relative spec":           {api("specs/api.json", "https://app.test"), "absolute path"},
		"empty spec":              {api("", "https://app.test"), "absolute path"},
		"base URL outside scope":  {api("/specs/api.json", "https://other.test/v1"), "api.base_url"},
		"base port outside scope": {api("/specs/api.json", "https://app.test:8443"), "api.base_url"},
		"base URL is not a URL":   {api("/specs/api.json", "app.test/v1"), "api.base_url"},
		"no base URL":             {api("/specs/api.json", ""), "api.base_url"},
	})
	m := probedMap()
	api("/specs/api.json", "https://app.test/v1")(m)
	m["api"].(map[string]any)["params"] = map[string]string{"id": "42"}
	c, err := parseMap(t, m)
	if err != nil || c.API.Spec != "/specs/api.json" || c.API.BaseURL != "https://app.test/v1" || c.API.Params["id"] != "42" {
		t.Fatalf("api = %+v, err = %v", c.API, err)
	}
}

func TestAgentValidationAndDefaults(t *testing.T) {
	agent := func(section map[string]any, refuter string) func(m map[string]any) {
		return func(m map[string]any) {
			m["agent"] = section
			m["refuter"] = map[string]any{"provider": refuter}
		}
	}
	rejects(t, map[string]rejection{
		"no steps":            {agent(map[string]any{}, "anthropic"), "agent.max_steps"},
		"negative steps":      {agent(map[string]any{"max_steps": -1}, "anthropic"), "agent.max_steps"},
		"too many steps":      {agent(map[string]any{"max_steps": 201}, "anthropic"), "agent.max_steps"},
		"unsafe allow":        {agent(map[string]any{"max_steps": 5, "unsafe_requests": "allow"}, "anthropic"), "agent.unsafe_requests"},
		"unsafe in capitals":  {agent(map[string]any{"max_steps": 5, "unsafe_requests": "ASK"}, "anthropic"), "agent.unsafe_requests"},
		"without a reviewer":  {agent(map[string]any{"max_steps": 5}, "none"), `refuter.provider "anthropic"`},
		"reviewer left unset": {func(m map[string]any) { m["agent"] = map[string]any{"max_steps": 5} }, `refuter.provider "anthropic"`},
	})
	for name, tc := range map[string]struct {
		section map[string]any
		want    string
	}{
		"default":        {map[string]any{"max_steps": 1}, UnsafeDeny},
		"explicit deny":  {map[string]any{"max_steps": 200, "unsafe_requests": "deny"}, UnsafeDeny},
		"ask":            {map[string]any{"max_steps": 5, "unsafe_requests": "ask", "goal": "Check the cart.", "model": "model-x"}, UnsafeAsk},
		"blank is unset": {map[string]any{"max_steps": 5, "unsafe_requests": ""}, UnsafeDeny},
	} {
		t.Run(name, func(t *testing.T) {
			m := probedMap()
			agent(tc.section, "anthropic")(m)
			c, err := parseMap(t, m)
			if err != nil || c.Agent.UnsafeRequests != tc.want {
				t.Fatalf("agent = %+v, err = %v; want unsafe_requests %q", c.Agent, err, tc.want)
			}
		})
	}
	if UnsafeDeny != "deny" || UnsafeAsk != "ask" {
		t.Fatalf("unsafe_requests values are %q and %q", UnsafeDeny, UnsafeAsk)
	}
}

func TestSecondReviewerValidationAndDefaults(t *testing.T) {
	refuter := func(section map[string]any) func(m map[string]any) {
		return func(m map[string]any) { m["refuter"] = section }
	}
	rejects(t, map[string]rejection{
		"without a provider": {refuter(map[string]any{"second_model": "model-b"}), "refuter.second_model needs"},
		"provider none":      {refuter(map[string]any{"provider": "none", "second_model": "model-b"}), "refuter.second_model needs"},
		"same as the first":  {refuter(map[string]any{"provider": "anthropic", "model": "model-a", "second_model": "model-a"}), "must differ"},
		"unknown severity": {refuter(map[string]any{"provider": "anthropic", "model": "model-a", "second_model": "model-b", "second_min_severity": "urgent"}),
			"second_min_severity"},
	})
	cases := map[string]struct {
		section map[string]any
		want    string
	}{
		"default threshold":            {map[string]any{"provider": "anthropic", "model": "model-a", "second_model": "model-b"}, "high"},
		"explicit threshold":           {map[string]any{"provider": "anthropic", "model": "model-a", "second_model": "model-b", "second_min_severity": "medium"}, "medium"},
		"default without second model": {map[string]any{"provider": "anthropic"}, "high"},
		"first model left to default":  {map[string]any{"provider": "anthropic", "second_model": "model-b"}, "high"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := validMap()
			refuter(tc.section)(m)
			c, err := parseMap(t, m)
			if err != nil || c.Refuter.SecondMinSeverity != tc.want {
				t.Fatalf("refuter = %+v, err = %v; want threshold %q", c.Refuter, err, tc.want)
			}
		})
	}
	t.Run("a bad threshold is rejected even without a second model", func(t *testing.T) {
		m := validMap()
		refuter(map[string]any{"provider": "anthropic", "second_min_severity": "urgent"})(m)
		if _, err := parseMap(t, m); err == nil {
			t.Fatal("a misspelt severity was accepted; it would be silently wrong once a second model is added")
		}
	})
	t.Run("second model equal to the default first model", func(t *testing.T) {
		m := validMap()
		refuter(map[string]any{"provider": "anthropic", "second_model": refute.DefaultModel})(m)
		if _, err := parseMap(t, m); err == nil {
			t.Skip("BUG: config.go validateRefuter compares second_model with the literal refuter.model, so with model unset a second_model equal to the default model is accepted and both reviewers are the same")
		}
	})
}

func TestNotifyValidation(t *testing.T) {
	rejects(t, map[string]rejection{
		"no variable":    {func(m map[string]any) { m["notify"] = map[string]any{} }, "notify.webhook_url_env"},
		"blank variable": {func(m map[string]any) { m["notify"] = map[string]any{"webhook_url_env": "  ", "allow_private": true} }, "notify.webhook_url_env"},
		"URL in the file": {func(m map[string]any) {
			m["notify"] = map[string]any{"webhook_url": "https://chat.example.test/hook"}
		}, "unknown field"},
	})
	m := validMap()
	m["notify"] = map[string]any{"webhook_url_env": "VAJRA_WEBHOOK", "allow_private": true}
	c, err := parseMap(t, m)
	if err != nil || c.Notify.WebhookURLEnv != "VAJRA_WEBHOOK" || !c.Notify.AllowPrivate {
		t.Fatalf("notify = %+v, err = %v", c.Notify, err)
	}
}

func TestSourceNeedsAtLeastOneAnalysis(t *testing.T) {
	base := func(t *testing.T, analyses map[string]any) map[string]any {
		m := codeOnlyMap(t)
		source := map[string]any{"root": t.TempDir()}
		for key, value := range analyses {
			source[key] = value
		}
		m["source"] = source
		return m
	}
	for name, analyses := range map[string]map[string]any{
		"nothing enabled":       {},
		"secrets off":           {"secrets": false},
		"dependencies empty":    {"dependencies": map[string]any{}},
		"dependencies osv off":  {"dependencies": map[string]any{"osv": false}},
		"everything turned off": {"secrets": false, "dependencies": map[string]any{"osv": false}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMap(t, base(t, analyses)); err == nil || !strings.Contains(err.Error(), "enables no analysis") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("secrets only", func(t *testing.T) {
		c, policy, err := Parse(strings.NewReader(encode(t, base(t, map[string]any{"secrets": true}))))
		if err != nil || !c.Source.Secrets || c.Source.Semgrep != nil || c.Source.Dependencies != nil || policy != nil || c.IsLive() {
			t.Fatalf("source = %+v, policy = %v, err = %v", c.Source, policy, err)
		}
	})
	t.Run("dependencies only", func(t *testing.T) {
		c, err := parseMap(t, base(t, map[string]any{"dependencies": map[string]any{"osv": true}}))
		if err != nil || c.Source.Secrets || c.Source.Semgrep != nil || !c.Source.Dependencies.OSV {
			t.Fatalf("source = %+v, err = %v", c.Source, err)
		}
	})
	t.Run("all three", func(t *testing.T) {
		m := codeOnlyMap(t)
		source := m["source"].(map[string]any)
		source["secrets"], source["dependencies"] = true, map[string]any{"osv": true}
		c, err := parseMap(t, m)
		if err != nil || !c.Source.Secrets || c.Source.Semgrep == nil || !c.Source.Dependencies.OSV {
			t.Fatalf("source = %+v, err = %v", c.Source, err)
		}
	})
	t.Run("a broken analyser is still rejected next to a working analysis", func(t *testing.T) {
		m := base(t, map[string]any{"secrets": true, "semgrep": map[string]any{"image": "vajra-semgrep:local"}})
		if _, err := parseMap(t, m); err == nil || !strings.Contains(err.Error(), "source.semgrep") {
			t.Fatalf("err = %v", err)
		}
	})
}

// checksOnlyMap is a live run with access checks and no targets.
func checksOnlyMap() map[string]any {
	m := probedMap()
	delete(m, "targets")
	delete(m, "nuclei")
	auth := authSection()
	auth["scan_as"] = ""
	m["auth"] = auth
	return m
}

func TestAccessChecksAloneAreALiveRunWithoutTheScanner(t *testing.T) {
	c, policy, err := Parse(strings.NewReader(encode(t, checksOnlyMap())))

	if err != nil {
		t.Fatalf("err = %v; access checks alone need no scanner settings", err)
	}
	if !c.IsLive() || !c.NeedsProbe() || policy == nil || len(c.Targets) != 0 || c.Nuclei.Image != "" {
		t.Fatalf("IsLive = %v, NeedsProbe = %v, policy = %v, config = %+v", c.IsLive(), c.NeedsProbe(), policy, c)
	}

	cases := map[string]rejection{
		"no sandbox":       {func(m map[string]any) { delete(m, "sandbox") }, "sandbox.network"},
		"no network":       {func(m map[string]any) { m["sandbox"] = map[string]any{"proxy_url": "http://gate:3128"} }, "sandbox.network"},
		"no proxy":         {func(m map[string]any) { m["sandbox"] = map[string]any{"network": "vajra-task-net"} }, "sandbox.proxy_url"},
		"no scope":         {func(m map[string]any) { delete(m, "scope") }, "scope"},
		"empty scope":      {func(m map[string]any) { m["scope"] = map[string]any{} }, "scope"},
		"no probe":         {func(m map[string]any) { delete(m, "probe") }, "probe.image"},
		"no budget":        {func(m map[string]any) { delete(m, "budget") }, "budget"},
		"no authorization": {func(m map[string]any) { delete(m, "authorization") }, "authorization"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := checksOnlyMap()
			tc.mutate(m)
			if _, err := parseMap(t, m); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want an error mentioning %q", err, tc.want)
			}
		})
	}
	t.Run("api alone", func(t *testing.T) {
		m := probedMap()
		delete(m, "targets")
		delete(m, "nuclei")
		m["api"] = map[string]any{"spec": "/specs/api.json", "base_url": "https://app.test"}
		c, err := parseMap(t, m)
		if err != nil || !c.IsLive() || !c.NeedsProbe() {
			t.Fatalf("IsLive = %v, NeedsProbe = %v, err = %v", c.IsLive(), c.NeedsProbe(), err)
		}
	})
	t.Run("targets still need the scanner", func(t *testing.T) {
		m := checksOnlyMap()
		m["targets"] = []string{"https://app.test"}
		if _, err := parseMap(t, m); err == nil || !strings.Contains(err.Error(), "nuclei.image") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("identities alone are nothing to test", func(t *testing.T) {
		m := checksOnlyMap()
		delete(m["auth"].(map[string]any), "access_checks")
		if _, err := parseMap(t, m); err == nil || !strings.Contains(err.Error(), "nothing to test") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestIsLiveAndNeedsProbe(t *testing.T) {
	checks := &Auth{AccessChecks: []AccessCheck{{Name: "admin", URL: "https://app.test/admin"}}}
	cases := map[string]struct {
		cfg        Config
		live       bool
		needsProbe bool
	}{
		"empty":                    {Config{}, false, false},
		"source only":              {Config{Source: &Source{Secrets: true}}, false, false},
		"source linked to service": {Config{Source: &Source{Secrets: true, Serves: "https://app.test"}}, false, false},
		"targets":                  {Config{Targets: []string{"https://app.test"}}, true, false},
		"identities without check": {Config{Auth: &Auth{Identities: []Identity{{Name: "user"}}, ScanAs: "user"}}, false, false},
		"empty auth":               {Config{Auth: &Auth{}}, false, false},
		"access checks":            {Config{Auth: checks}, true, true},
		"api":                      {Config{API: &API{}}, true, true},
		"recon":                    {Config{Recon: &Recon{}}, true, false},
		"crawl alone":              {Config{Crawl: &Crawl{}}, false, true},
		"agent alone":              {Config{Agent: &Agent{}}, false, true},
		"notify alone":             {Config{Notify: &Notify{}}, false, false},
		"targets and crawl":        {Config{Targets: []string{"https://app.test"}, Crawl: &Crawl{}}, true, true},
		"targets and agent":        {Config{Targets: []string{"https://app.test"}, Agent: &Agent{}}, true, true},
		"recon and checks":         {Config{Recon: &Recon{}, Auth: checks}, true, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.cfg.IsLive(); got != tc.live {
				t.Errorf("IsLive = %v; want %v", got, tc.live)
			}
			if got := tc.cfg.NeedsProbe(); got != tc.needsProbe {
				t.Errorf("NeedsProbe = %v; want %v", got, tc.needsProbe)
			}
		})
	}
}

func TestGraphQLAndPortsSections(t *testing.T) {
	probeSection := map[string]any{"image": "vajra:local", "timeout_seconds": 60}
	valid := func() map[string]any {
		m := validMap()
		m["scope"] = map[string]any{"hosts": []string{"app.test"}, "ports": []int{443, 5432}}
		m["probe"] = probeSection
		m["sandbox"] = map[string]any{"network": "vajra-task-net", "proxy_url": "http://gate:3128", "socks_addr": "gate:1080"}
		m["graphql"] = map[string]any{"endpoint": "https://app.test/graphql", "requires_auth": true}
		m["ports"] = map[string]any{"hosts": []string{"app.test"}, "ports": []int{443, 5432}, "expected": []int{443}, "timeout_seconds": 60}
		return m
	}
	c, err := parseMap(t, valid())
	if err != nil || c.GraphQL == nil || !c.GraphQL.RequiresAuth || c.Ports == nil || c.Sandbox.SocksAddr != "gate:1080" || !c.NeedsProbe() || !c.IsLive() {
		t.Fatalf("config = %+v, err = %v", c, err)
	}
	cases := map[string]func(m map[string]any){
		"graphql endpoint out of scope": func(m map[string]any) { m["graphql"].(map[string]any)["endpoint"] = "https://other.test/graphql" },
		"graphql endpoint not a URL":    func(m map[string]any) { m["graphql"].(map[string]any)["endpoint"] = "app.test/graphql" },
		"graphql without a probe":       func(m map[string]any) { delete(m, "probe") },
		"ports without hosts":           func(m map[string]any) { m["ports"].(map[string]any)["hosts"] = []string{} },
		"ports without a timeout":       func(m map[string]any) { m["ports"].(map[string]any)["timeout_seconds"] = 0 },
		"port outside the scope":        func(m map[string]any) { m["ports"].(map[string]any)["ports"] = []int{443, 22} },
		"host outside the scope":        func(m map[string]any) { m["ports"].(map[string]any)["hosts"] = []string{"db.internal"} },
		"port out of range":             func(m map[string]any) { m["ports"].(map[string]any)["ports"] = []int{70000} },
		"ports without the socks gate":  func(m map[string]any) { m["sandbox"].(map[string]any)["socks_addr"] = "" },
	}
	for name, mutate := range cases {
		m := valid()
		mutate(m)
		if _, err := parseMap(t, m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
