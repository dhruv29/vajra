package notify

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// Resolver looks up the addresses of a host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// dialFunc opens a connection to an address of the form "ip:port".
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// nonPublic lists the ranges a webhook may not resolve to unless the operator
// allows private addresses. A webhook URL is configuration, and a URL that
// leads inward would turn a notification into a request against the
// operator's own network or their cloud metadata service.
var nonPublic = mustPrefixes(
	"0.0.0.0/8",      // "this network", unspecified
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local, cloud metadata (169.254.169.254)
	"10.0.0.0/8",     // private
	"172.16.0.0/12",  // private
	"192.168.0.0/16", // private
	"100.64.0.0/10",  // carrier-grade NAT
	"192.0.0.0/24",   // IETF protocol assignments
	"198.18.0.0/15",  // benchmarking
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, broadcast
	"::/96",          // unspecified, loopback and IPv4-compatible addresses
	"fc00::/7",       // unique local
	"fe80::/10",      // link-local
	"ff00::/8",       // multicast
	// Ranges that carry an IPv4 address inside an IPv6 one. They could smuggle
	// a loopback or metadata address past the IPv4 rules.
	"64:ff9b::/96",   // NAT64
	"64:ff9b:1::/48", // local-use NAT64
	"2002::/16",      // 6to4
	"2001::/32",      // Teredo
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// isPublic reports whether addr is outside every non-public range. The
// address is compared in its plain form: an IPv4-mapped IPv6 address is
// judged as the IPv4 address it reaches, and a zone is dropped because a
// prefix never matches a zoned address.
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// guard dials only addresses that passed the check. It resolves the name
// itself, checks every address the name resolved to, and then connects to a
// checked address rather than to the name, so a second DNS answer cannot
// redirect the connection after the check.
type guard struct {
	resolver     Resolver
	dial         dialFunc
	allowPrivate bool
}

// dialContext is the transport's dialer. One non-public address among the
// answers refuses the whole name: a name that sometimes points inward is not
// one to send to.
func (g *guard) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("notify: malformed address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("notify: malformed port for %s", host)
	}
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if !g.allowPrivate {
		for _, addr := range addrs {
			if !isPublic(addr) {
				return nil, fmt.Errorf("notify: %s resolves to %s, which is not a public address; allow private addresses if the webhook is internal", host, addr)
			}
		}
	}
	var lastErr error
	for _, addr := range addrs {
		pinned := netip.AddrPortFrom(addr.Unmap(), uint16(port)).String()
		conn, err := g.dial(ctx, network, pinned)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("notify: connect to %s: %w", host, lastErr)
}

func (g *guard) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	addrs, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("notify: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("notify: resolve %s: no addresses", host)
	}
	return addrs, nil
}
