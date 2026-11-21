package scope

import (
	"net/netip"
	"testing"
)

func mustPolicy(t *testing.T, c Config) *Policy {
	t.Helper()
	p, err := New(c)
	if err != nil {
		t.Fatalf("New(%+v): %v", c, err)
	}
	return p
}

func TestNewRejectsUnsafeConfigs(t *testing.T) {
	cases := map[string]Config{
		"empty scope":              {},
		"bare wildcard":            {Hosts: []string{"*"}},
		"top-level wildcard":       {Hosts: []string{"*.com"}},
		"mid wildcard":             {Hosts: []string{"app.*.example.com"}},
		"address listed as host":   {Hosts: []string{"10.0.0.5"}},
		"host with scheme":         {Hosts: []string{"https://app.example.com"}},
		"host with path":           {Hosts: []string{"app.example.com/admin"}},
		"everything CIDR":          {CIDRs: []string{"0.0.0.0/0"}},
		"loopback CIDR":            {CIDRs: []string{"127.0.0.0/8"}},
		"metadata CIDR":            {CIDRs: []string{"169.254.169.254/32"}},
		"ipv6 everything CIDR":     {CIDRs: []string{"::/0"}},
		"malformed CIDR":           {CIDRs: []string{"10.0.0.0"}},
		"mapped ipv4 CIDR":         {CIDRs: []string{"::ffff:10.0.0.0/104"}},
		"NAT64 CIDR":               {CIDRs: []string{"64:ff9b::/96"}},
		"6to4 CIDR":                {CIDRs: []string{"2002::/16"}},
		"numeric wildcard base":    {Hosts: []string{"*.0.1"}},
		"numeric host":             {Hosts: []string{"2130706433"}},
		"port zero":                {Hosts: []string{"app.example.com"}, Ports: []int{0}},
		"port above range":         {Hosts: []string{"app.example.com"}, Ports: []int{70000}},
		"empty host entry":         {Hosts: []string{"  "}},
		"label starts with a dash": {Hosts: []string{"-app.example.com"}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatalf("New(%+v) succeeded; want an error", cfg)
			}
		})
	}
}

func TestCheckTarget(t *testing.T) {
	p := mustPolicy(t, Config{
		Hosts: []string{"App.Example.com.", "*.staging.example.com"},
		CIDRs: []string{"10.20.0.0/16"},
		Ports: []int{443, 8443},
	})
	cases := []struct {
		name    string
		host    string
		port    uint16
		allowed bool
	}{
		{"exact host", "app.example.com", 443, true},
		{"exact host is case-insensitive", "APP.example.COM", 443, true},
		{"trailing dot", "app.example.com.", 443, true},
		{"wildcard sub-domain", "api.staging.example.com", 8443, true},
		{"wildcard nested sub-domain", "a.b.staging.example.com", 443, true},
		{"wildcard does not match the apex", "staging.example.com", 443, false},
		{"suffix look-alike", "evilstaging.example.com", 443, false},
		{"appended domain", "app.example.com.evil.test", 443, false},
		{"unlisted host", "other.example.com", 443, false},
		{"port not listed", "app.example.com", 80, false},
		{"literal inside CIDR", "10.20.3.4", 443, true},
		{"literal outside CIDR", "10.21.0.1", 443, false},
		{"public literal is not implied", "93.184.216.34", 443, false},
		{"loopback literal", "127.0.0.1", 443, false},
		{"metadata literal", "169.254.169.254", 443, false},
		{"bracketed ipv6 loopback", "[::1]", 443, false},
		{"ipv4-mapped loopback", "::ffff:127.0.0.1", 443, false},
		{"ipv4-mapped scoped address", "::ffff:10.20.3.4", 443, true},
		{"empty host", "", 443, false},
		{"literal with a trailing dot is normalised", "10.20.3.4.", 443, true},
		{"literal with a leading space", " 10.20.3.4", 443, false},
		{"host with a leading space", " app.example.com", 443, false},
		{"zoned literal", "fe80::1%eth0", 443, false},
		{"decimal address", "2130706433", 443, false},
		{"short dotted address", "127.1", 443, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.CheckTarget(tc.host, tc.port)
			if tc.allowed && err != nil {
				t.Fatalf("CheckTarget(%q, %d) = %v; want allowed", tc.host, tc.port, err)
			}
			if !tc.allowed && !IsDenied(err) {
				t.Fatalf("CheckTarget(%q, %d) = %v; want a denial", tc.host, tc.port, err)
			}
		})
	}
}

func TestDefaultPortsAreWebOnly(t *testing.T) {
	p := mustPolicy(t, Config{Hosts: []string{"app.example.com"}})
	for port, allowed := range map[uint16]bool{80: true, 443: true, 22: false, 5432: false} {
		err := p.CheckTarget("app.example.com", port)
		if allowed != (err == nil) {
			t.Errorf("port %d: err = %v; want allowed=%v", port, err, allowed)
		}
	}
}

func TestCheckResolved(t *testing.T) {
	p := mustPolicy(t, Config{
		Hosts: []string{"app.example.com"},
		CIDRs: []string{"192.168.50.0/24", "fd00:50::/64"},
	})
	cases := []struct {
		name    string
		addr    string
		allowed bool
	}{
		{"public address", "93.184.216.34", true},
		{"public ipv6 address", "2606:2800:220:1::1", true},
		{"private address inside a scoped CIDR", "192.168.50.7", true},
		{"unique-local inside a scoped CIDR", "fd00:50::9", true},
		{"private address outside scope", "192.168.1.1", false},
		{"rfc1918 ten-net", "10.0.0.1", false},
		{"carrier-grade NAT", "100.64.0.1", false},
		{"loopback", "127.0.0.1", false},
		{"cloud metadata", "169.254.169.254", false},
		{"ipv6 loopback", "::1", false},
		{"ipv6 link-local", "fe80::1", false},
		{"unique-local outside scope", "fd12::1", false},
		{"ipv4-mapped loopback", "::ffff:127.0.0.1", false},
		{"ipv4-mapped metadata", "::ffff:169.254.169.254", false},
		{"NAT64-embedded address", "64:ff9b::7f00:1", false},
		{"local NAT64-embedded address", "64:ff9b:1::7f00:1", false},
		{"ipv4-compatible loopback", "::7f00:1", false},
		{"ipv4-compatible dotted loopback", "::127.0.0.1", false},
		{"6to4-embedded loopback", "2002:7f00:1::", false},
		{"teredo", "2001::1", false},
		{"azure platform endpoint", "168.63.129.16", false},
		{"zoned loopback", "::1%lo", false},
		{"zoned link-local", "fe80::1%eth0", false},
		{"unspecified", "0.0.0.0", false},
		{"multicast", "224.0.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.CheckResolved("app.example.com", netip.MustParseAddr(tc.addr))
			if tc.allowed && err != nil {
				t.Fatalf("CheckResolved(%s) = %v; want allowed", tc.addr, err)
			}
			if !tc.allowed && !IsDenied(err) {
				t.Fatalf("CheckResolved(%s) = %v; want a denial", tc.addr, err)
			}
		})
	}
}

func TestCheckResolvedRejectsZeroAddr(t *testing.T) {
	p := mustPolicy(t, Config{Hosts: []string{"app.example.com"}})
	if err := p.CheckResolved("app.example.com", netip.Addr{}); !IsDenied(err) {
		t.Fatalf("zero address: err = %v; want a denial", err)
	}
}

func TestDeniedErrorNamesTargetAndReason(t *testing.T) {
	err := (&Denied{Target: "x:1", Reason: "why"}).Error()
	if err != "scope denied x:1: why" {
		t.Fatalf("Error() = %q", err)
	}
}
