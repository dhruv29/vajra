// Package recon discovers hosts that are in scope but were not listed by
// name. It only ever looks under domains the operator put in scope with a
// wildcard, and it keeps a name only when every address it resolves to is one
// the scope policy accepts.
//
// Discovery here is DNS only. The lookups are made from the machine running
// Vajra, not through the egress gate, because they are queries about names in
// scope and send nothing to the hosts themselves.
package recon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/dhruv29/vajra/internal/scope"
)

const (
	defaultConcurrency = 16
	maxNamesCeiling    = 5000
	wildcardProbeBytes = 8
)

// DefaultWords are common sub-domain labels, used when the operator supplies
// no list of their own.
var DefaultWords = []string{
	"www", "api", "app", "admin", "portal", "auth", "login", "sso", "id", "accounts",
	"dev", "test", "qa", "uat", "stage", "staging", "preprod", "demo", "sandbox", "beta",
	"internal", "intranet", "vpn", "gateway", "gw", "proxy", "edge", "cdn", "static", "assets",
	"img", "media", "files", "docs", "help", "support", "status", "monitor", "metrics", "grafana",
	"kibana", "jenkins", "ci", "git", "gitlab", "registry", "mail", "smtp", "webmail", "mx",
	"shop", "store", "pay", "payments", "billing", "checkout", "orders", "partners", "m", "mobile",
	"db", "data", "search", "graphql", "ws", "backend", "service", "services", "v1", "v2",
}

// Resolver looks up the addresses of a host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Host is one discovered name.
type Host struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// Options configures discovery.
type Options struct {
	Resolver Resolver
	// Words are the labels to try under each wildcard base. Empty means
	// DefaultWords.
	Words []string
	// MaxNames caps how many candidate names are looked up in total.
	MaxNames    int
	Concurrency int
}

// Result is what discovery found.
type Result struct {
	Hosts []Host `json:"hosts"`
	// Tried is how many names were looked up.
	Tried int `json:"tried"`
	// Rejected lists names that resolve but to an address the policy does not
	// accept, and so were left out.
	Rejected []string `json:"rejected"`
	// CatchAll lists bases where every name resolves, which makes guessing
	// names there meaningless; nothing is reported under them.
	CatchAll []string `json:"catch_all"`
}

// Discover looks for sub-domains under the policy's wildcard bases.
func Discover(ctx context.Context, policy *scope.Policy, opts Options) (Result, error) {
	if policy == nil || opts.Resolver == nil {
		return Result{}, errors.New("recon: a scope policy and a resolver are required")
	}
	if opts.MaxNames < 1 || opts.MaxNames > maxNamesCeiling {
		return Result{}, fmt.Errorf("recon: max names must be between 1 and %d", maxNamesCeiling)
	}
	words := cleanWords(opts.Words)
	if len(words) == 0 {
		words = DefaultWords
	}
	result := Result{Hosts: []Host{}, Rejected: []string{}, CatchAll: []string{}}
	var candidates []string
	for _, base := range policy.WildcardBases() {
		catchAll, err := resolvesAnything(ctx, opts.Resolver, base)
		if err != nil {
			return Result{}, err
		}
		if catchAll {
			result.CatchAll = append(result.CatchAll, base)
			continue
		}
		for _, word := range words {
			candidates = append(candidates, word+"."+base)
		}
	}
	if len(candidates) > opts.MaxNames {
		candidates = candidates[:opts.MaxNames]
	}
	result.Tried = len(candidates)
	lookups := lookupAll(ctx, opts, candidates)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	for i, name := range candidates {
		addrs := lookups[i]
		if len(addrs) == 0 {
			continue
		}
		if accepted(policy, name, addrs) {
			result.Hosts = append(result.Hosts, Host{Name: name, Addrs: addrStrings(addrs)})
		} else {
			result.Rejected = append(result.Rejected, name)
		}
	}
	sort.Slice(result.Hosts, func(i, j int) bool { return result.Hosts[i].Name < result.Hosts[j].Name })
	sort.Strings(result.Rejected)
	return result, nil
}

// resolvesAnything looks up a random label under base. If that resolves, the
// zone answers for every name and guessing tells us nothing.
func resolvesAnything(ctx context.Context, resolver Resolver, base string) (bool, error) {
	raw := make([]byte, wildcardProbeBytes)
	if _, err := rand.Read(raw); err != nil {
		return false, fmt.Errorf("recon: random label: %w", err)
	}
	addrs, _ := resolver.LookupNetIP(ctx, "ip", "vajra-"+hex.EncodeToString(raw)+"."+base)
	return len(addrs) > 0, ctx.Err()
}

// lookupAll resolves every name with bounded concurrency. A name that does
// not resolve gives an empty entry.
func lookupAll(ctx context.Context, opts Options, names []string) [][]netip.Addr {
	workers := opts.Concurrency
	if workers < 1 {
		workers = defaultConcurrency
	}
	out := make([][]netip.Addr, len(names))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					continue
				}
				out[i], _ = opts.Resolver.LookupNetIP(ctx, "ip", names[i])
			}
		}()
	}
	for i := range names {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

// accepted reports whether name is in scope and every address is acceptable.
func accepted(policy *scope.Policy, name string, addrs []netip.Addr) bool {
	ports := policy.Ports()
	if len(ports) == 0 || policy.CheckTarget(name, ports[0]) != nil {
		return false
	}
	for _, addr := range addrs {
		if policy.CheckResolved(name, addr) != nil {
			return false
		}
	}
	return true
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap().String())
	}
	sort.Strings(out)
	return out
}

// cleanWords keeps labels that are valid DNS labels, lower-cased and unique.
func cleanWords(words []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range words {
		w = strings.ToLower(strings.TrimSpace(w))
		if !validLabel(w) || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

// URLs turns discovered hosts into candidate targets, one per in-scope port.
// Port 80 gets http and every other port https.
func URLs(policy *scope.Policy, hosts []Host) []string {
	var out []string
	for _, h := range hosts {
		for _, port := range policy.Ports() {
			switch port {
			case 80:
				out = append(out, "http://"+h.Name)
			case 443:
				out = append(out, "https://"+h.Name)
			default:
				out = append(out, fmt.Sprintf("https://%s:%d", h.Name, port))
			}
		}
	}
	return out
}
