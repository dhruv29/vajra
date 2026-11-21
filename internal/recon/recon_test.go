package recon

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dhruv29/vajra/internal/scope"
)

// zone answers from a table and counts lookups. catchAll makes every name
// under that base resolve.
type zone struct {
	mu       sync.Mutex
	records  map[string][]string
	catchAll string
	lookups  []string
}

func (z *zone) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	z.mu.Lock()
	z.lookups = append(z.lookups, host)
	z.mu.Unlock()
	raw, ok := z.records[host]
	if !ok && z.catchAll != "" && strings.HasSuffix(host, "."+z.catchAll) {
		raw, ok = []string{"203.0.113.99"}, true
	}
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, r := range raw {
		out = append(out, netip.MustParseAddr(r))
	}
	return out, nil
}

func policy(t *testing.T, hosts ...string) *scope.Policy {
	t.Helper()
	p, err := scope.New(scope.Config{Hosts: hosts, CIDRs: []string{"10.50.0.0/16"}, Ports: []int{443, 8443, 80}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiscoverKeepsOnlyNamesWhoseEveryAddressIsAcceptable(t *testing.T) {
	z := &zone{records: map[string][]string{
		"api.example.com":      {"203.0.113.10", "2001:db8::10"},
		"admin.example.com":    {"10.50.1.2"},                 // private, but inside a scoped CIDR
		"internal.example.com": {"192.168.1.5"},               // private and not in scope
		"vpn.example.com":      {"203.0.113.11", "127.0.0.1"}, // one bad address taints the name
		"other.test":           {"203.0.113.12"},
	}}

	result, err := Discover(context.Background(), policy(t, "*.example.com"), Options{Resolver: z, MaxNames: 500})

	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, h := range result.Hosts {
		names = append(names, h.Name)
	}
	if !slices.Equal(names, []string{"admin.example.com", "api.example.com"}) {
		t.Fatalf("hosts = %v", names)
	}
	if !slices.Equal(result.Hosts[1].Addrs, []string{"2001:db8::10", "203.0.113.10"}) {
		t.Fatalf("addrs = %v", result.Hosts[1].Addrs)
	}
	if !slices.Equal(result.Rejected, []string{"internal.example.com", "vpn.example.com"}) {
		t.Fatalf("rejected = %v", result.Rejected)
	}
	if result.Tried != len(DefaultWords) || len(result.CatchAll) != 0 {
		t.Fatalf("tried = %d, catch-all = %v", result.Tried, result.CatchAll)
	}
	for _, name := range z.lookups {
		if !strings.HasSuffix(name, ".example.com") {
			t.Fatalf("looked up %q, which is outside the wildcard base", name)
		}
	}
}

func TestDiscoverSkipsCatchAllZones(t *testing.T) {
	z := &zone{catchAll: "example.com", records: map[string][]string{"api.dev.example.org": {"203.0.113.10"}}}

	result, err := Discover(context.Background(), policy(t, "*.example.com", "*.dev.example.org"),
		Options{Resolver: z, MaxNames: 500, Words: []string{"api", "www"}})

	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.CatchAll, []string{"example.com"}) || len(result.Hosts) != 1 || result.Hosts[0].Name != "api.dev.example.org" {
		t.Fatalf("result = %+v", result)
	}
	if result.Tried != 2 {
		t.Fatalf("tried = %d; no names may be guessed under a catch-all zone", result.Tried)
	}
}

func TestDiscoverUsesCleanedWordsAndRespectsTheCap(t *testing.T) {
	z := &zone{records: map[string][]string{"api.example.com": {"203.0.113.10"}}}
	words := []string{" API ", "api", "bad label", "-lead", "trail-", "", "ok-1", strings.Repeat("x", 64), "a.b"}

	result, err := Discover(context.Background(), policy(t, "*.example.com"), Options{Resolver: z, MaxNames: 2, Words: words, Concurrency: 1})

	if err != nil || result.Tried != 2 || len(result.Hosts) != 1 {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	guessed := z.lookups[1:] // the first lookup is the catch-all probe
	if !slices.Equal(guessed, []string{"api.example.com", "ok-1.example.com"}) {
		t.Fatalf("looked up %v", guessed)
	}
}

func TestDiscoverWithNoWildcardsFindsNothingAndLooksUpNothing(t *testing.T) {
	z := &zone{}
	result, err := Discover(context.Background(), policy(t, "app.example.com"), Options{Resolver: z, MaxNames: 10})
	if err != nil || len(result.Hosts) != 0 || result.Hosts == nil || len(z.lookups) != 0 {
		t.Fatalf("result = %+v, err = %v, lookups = %v", result, err, z.lookups)
	}
}

func TestDiscoverValidatesOptionsAndHonoursCancellation(t *testing.T) {
	p := policy(t, "*.example.com")
	for name, call := range map[string]func() (Result, error){
		"nil policy": func() (Result, error) {
			return Discover(context.Background(), nil, Options{Resolver: &zone{}, MaxNames: 1})
		},
		"nil resolver": func() (Result, error) { return Discover(context.Background(), p, Options{MaxNames: 1}) },
		"zero cap":     func() (Result, error) { return Discover(context.Background(), p, Options{Resolver: &zone{}}) },
		"huge cap": func() (Result, error) {
			return Discover(context.Background(), p, Options{Resolver: &zone{}, MaxNames: maxNamesCeiling + 1})
		},
	} {
		if _, err := call(); err == nil {
			t.Errorf("%s: Discover succeeded", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, p, Options{Resolver: &zone{}, MaxNames: 10}); err == nil {
		t.Error("a cancelled discovery succeeded")
	}
}

func TestURLsCoverEveryScopedPort(t *testing.T) {
	got := URLs(policy(t, "*.example.com"), []Host{{Name: "api.example.com"}})
	want := []string{"http://api.example.com", "https://api.example.com", "https://api.example.com:8443"}
	if !slices.Equal(got, want) {
		t.Fatalf("urls = %v", got)
	}
}
