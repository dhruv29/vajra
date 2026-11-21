// Package scope decides which network targets a task may reach.
//
// The policy is deny-by-default: a target is allowed only when its host name
// or address is explicitly listed. Address ranges that can never be a
// legitimate test target (loopback, link-local and cloud metadata, multicast)
// are refused even when listed, and private ranges are refused unless a listed
// CIDR covers them. A host name that is allowed by name must still resolve to
// an address this policy accepts, which is what defeats DNS rebinding.
package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Config is the operator-supplied scope definition.
type Config struct {
	// Hosts are exact names ("app.example.com") or leading-wildcard names
	// ("*.example.com", which matches sub-domains but not the apex).
	Hosts []string `json:"hosts"`
	// CIDRs are address ranges. An IP-literal target must fall inside one.
	CIDRs []string `json:"cidrs"`
	// Ports allowed on any in-scope target. Empty means 80 and 443.
	Ports []int `json:"ports"`
}

// Denied reports that a target is outside the policy.
type Denied struct {
	Target string
	Reason string
}

func (d *Denied) Error() string {
	return fmt.Sprintf("scope denied %s: %s", d.Target, d.Reason)
}

// IsDenied reports whether err is, or wraps, a scope denial.
func IsDenied(err error) bool {
	var d *Denied
	return errors.As(err, &d)
}

// Policy is an immutable, validated scope definition.
type Policy struct {
	exact    map[string]struct{}
	suffixes []string
	nets     []netip.Prefix
	ports    map[uint16]struct{}
}

var defaultPorts = []int{80, 443}

// minWildcardLabels is the fewest labels a wildcard may leave fixed:
// "*.example.com" is accepted, "*.com" is not.
const minWildcardLabels = 2

// neverAllowed can not be a test target under any configuration.
var neverAllowed = mustPrefixes(
	"0.0.0.0/8",        // "this network"
	"127.0.0.0/8",      // loopback
	"169.254.0.0/16",   // link-local, cloud metadata
	"168.63.129.16/32", // Azure platform endpoint
	"192.88.99.0/24",   // 6to4 relay anycast
	"224.0.0.0/4",      // multicast
	"240.0.0.0/4",      // reserved, broadcast
	"::/96",            // unspecified, loopback and IPv4-compatible addresses
	"fe80::/10",        // link-local
	"ff00::/8",         // multicast
	// Ranges that carry an IPv4 address inside an IPv6 one. They could smuggle
	// a loopback or metadata address past the IPv4 rules, so none is a target.
	"64:ff9b::/96",   // NAT64
	"64:ff9b:1::/48", // local-use NAT64
	"2002::/16",      // 6to4
	"2001::/32",      // Teredo
)

// privateRanges are reachable only when a listed CIDR covers the address.
var privateRanges = mustPrefixes(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10", // carrier-grade NAT
	"192.0.0.0/24",  // IETF protocol assignments
	"198.18.0.0/15", // benchmarking
	"fc00::/7",      // unique local
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// New validates c and builds a Policy. An empty scope is an error: there is no
// "allow everything" configuration.
func New(c Config) (*Policy, error) {
	if len(c.Hosts) == 0 && len(c.CIDRs) == 0 {
		return nil, errors.New("scope: at least one host or CIDR is required")
	}
	p := &Policy{exact: map[string]struct{}{}, ports: map[uint16]struct{}{}}
	for _, h := range c.Hosts {
		if err := p.addHost(h); err != nil {
			return nil, err
		}
	}
	for _, raw := range c.CIDRs {
		pfx, err := parseCIDR(raw)
		if err != nil {
			return nil, err
		}
		p.nets = append(p.nets, pfx)
	}
	ports := c.Ports
	if len(ports) == 0 {
		ports = defaultPorts
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("scope: port %d is out of range", port)
		}
		p.ports[uint16(port)] = struct{}{}
	}
	return p, nil
}

func (p *Policy) addHost(raw string) error {
	h := NormalizeHost(strings.TrimSpace(raw))
	if h == "" {
		return errors.New("scope: empty host entry")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return fmt.Errorf("scope: %q is an address; list it under cidrs", raw)
	}
	if strings.HasPrefix(h, "*.") {
		base := h[2:]
		if !validName(base) || strings.Count(base, ".")+1 < minWildcardLabels {
			return fmt.Errorf("scope: wildcard %q is too broad or malformed", raw)
		}
		p.suffixes = append(p.suffixes, "."+base)
		return nil
	}
	if !validName(h) {
		return fmt.Errorf("scope: host %q is malformed", raw)
	}
	p.exact[h] = struct{}{}
	return nil
}

func parseCIDR(raw string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("scope: CIDR %q: %w", raw, err)
	}
	if pfx.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("scope: CIDR %q: write IPv4 ranges in IPv4 form", raw)
	}
	pfx = pfx.Masked()
	for _, blocked := range neverAllowed {
		if pfx.Overlaps(blocked) {
			return netip.Prefix{}, fmt.Errorf("scope: CIDR %q overlaps %s, which can never be a target", raw, blocked)
		}
	}
	return pfx, nil
}

// validName accepts DNS names made of letters, digits, hyphens and dots. The
// last label must contain a letter, so nothing a resolver could read as a
// numeric address is ever treated as a name.
func validName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	if !strings.ContainsFunc(labels[len(labels)-1], func(r rune) bool { return r >= 'a' && r <= 'z' }) {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// NormalizeHost returns the one form of a host that the policy checks and the
// gate then resolves and dials: lower case, no surrounding brackets, no
// trailing dot. Using the same string for the check and the connection is what
// keeps the two from disagreeing about the destination.
func NormalizeHost(h string) string {
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// CheckTarget is the name-level check, made before any DNS lookup. An
// IP-literal host must fall inside a listed CIDR; a name must be listed.
func (p *Policy) CheckTarget(host string, port uint16) error {
	target := fmt.Sprintf("%s:%d", host, port)
	if _, ok := p.ports[port]; !ok {
		return &Denied{Target: target, Reason: "port is not in scope"}
	}
	h := NormalizeHost(host)
	if addr, err := netip.ParseAddr(h); err == nil {
		if addr.Zone() != "" {
			return &Denied{Target: target, Reason: "zoned addresses are not targets"}
		}
		return p.checkLiteral(target, addr.Unmap())
	}
	if _, ok := p.exact[h]; ok {
		return nil
	}
	for _, suffix := range p.suffixes {
		if strings.HasSuffix(h, suffix) && validName(h) {
			return nil
		}
	}
	return &Denied{Target: target, Reason: "host is not in scope"}
}

func (p *Policy) checkLiteral(target string, addr netip.Addr) error {
	if containsAddr(neverAllowed, addr) {
		return &Denied{Target: target, Reason: "address range can never be a target"}
	}
	if !containsAddr(p.nets, addr) {
		return &Denied{Target: target, Reason: "address is not inside a scoped CIDR"}
	}
	return nil
}

// CheckResolved is the address-level check, made on every address a scoped
// host name resolved to. A public address is accepted because the name was
// already approved; a private one needs a listed CIDR.
func (p *Policy) CheckResolved(host string, addr netip.Addr) error {
	addr = addr.Unmap()
	target := fmt.Sprintf("%s (%s)", host, addr)
	if !addr.IsValid() {
		return &Denied{Target: target, Reason: "invalid address"}
	}
	if addr.Zone() != "" {
		return &Denied{Target: target, Reason: "resolves to a zoned address"}
	}
	if containsAddr(neverAllowed, addr) {
		return &Denied{Target: target, Reason: "resolves to a range that can never be a target"}
	}
	if containsAddr(p.nets, addr) {
		return nil
	}
	if containsAddr(privateRanges, addr) {
		return &Denied{Target: target, Reason: "resolves to a private address outside the scoped CIDRs"}
	}
	return nil
}

func containsAddr(nets []netip.Prefix, addr netip.Addr) bool {
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// WildcardBases returns the domains whose sub-domains are in scope, without
// the leading "*.". Discovery uses them to know where it may look.
func (p *Policy) WildcardBases() []string {
	out := make([]string, 0, len(p.suffixes))
	for _, suffix := range p.suffixes {
		out = append(out, strings.TrimPrefix(suffix, "."))
	}
	sort.Strings(out)
	return out
}

// Ports returns the ports that are in scope, in ascending order.
func (p *Policy) Ports() []uint16 {
	out := make([]uint16, 0, len(p.ports))
	for port := range p.ports {
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
