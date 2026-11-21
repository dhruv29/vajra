// Package egress is the network gate: every connection a task makes passes
// through it and is checked against the scope policy.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/dhruv29/vajra/internal/scope"
)

// Resolver looks up the addresses of a host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a connection to an address of the form "ip:port".
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Guard dials only targets the policy allows. It resolves the name itself,
// checks every address the name resolved to, and then connects to a checked
// address rather than to the name, so a second DNS answer cannot redirect the
// connection after the check.
type Guard struct {
	policy   *scope.Policy
	resolver Resolver
	dial     DialFunc
}

// NewGuard builds a Guard. A nil resolver or dial uses the system defaults.
func NewGuard(policy *scope.Policy, resolver Resolver, dial DialFunc) (*Guard, error) {
	if policy == nil {
		return nil, errors.New("egress: a scope policy is required")
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return &Guard{policy: policy, resolver: resolver, dial: dial}, nil
}

// CheckTarget is the name-level policy check for "host:port".
func (g *Guard) CheckTarget(address string) error {
	host, port, err := splitHostPort(address)
	if err != nil {
		return err
	}
	return g.policy.CheckTarget(host, port)
}

// DialContext connects to address ("host:port") if, and only if, the policy
// allows both the name and every address it resolves to.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	if err := g.policy.CheckTarget(host, port); err != nil {
		return nil, err
	}
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if err := g.policy.CheckResolved(host, addr); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, addr := range addrs {
		pinned := netip.AddrPortFrom(addr.Unmap(), port).String()
		conn, err := g.dial(ctx, network, pinned)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("egress: dial %s: %w", address, lastErr)
}

func (g *Guard) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	addrs, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("egress: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("egress: resolve %s: no addresses", host)
	}
	return addrs, nil
}

func splitHostPort(address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, &scope.Denied{Target: address, Reason: "malformed address"}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, &scope.Denied{Target: address, Reason: "malformed port"}
	}
	return host, uint16(port), nil
}
