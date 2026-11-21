package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/dhruv29/vajra/internal/scope"
)

// fakeResolver answers from a fixed table, so tests never touch real DNS.
type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	raw, ok := f[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, r := range raw {
		out = append(out, netip.MustParseAddr(r))
	}
	return out, nil
}

// redirectDialer records the address the guard chose and connects to a local
// test server instead, standing in for the real network.
type redirectDialer struct {
	mu     sync.Mutex
	dialed []string
	to     string
	err    error
}

func (d *redirectDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.to)
}

func (d *redirectDialer) addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

type fixture struct {
	proxyURL *url.URL
	dialer   *redirectDialer
	sink     *MemorySink
}

func newFixture(t *testing.T, upstream string, resolver fakeResolver) fixture {
	t.Helper()
	policy, err := scope.New(scope.Config{Hosts: []string{"app.test", "rebind.test", "mixed.test"}})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &redirectDialer{to: upstream}
	guard, err := NewGuard(policy, resolver, dialer.dial)
	if err != nil {
		t.Fatal(err)
	}
	sink := &MemorySink{}
	proxy, err := NewProxy(guard, sink)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{proxyURL: proxyURL, dialer: dialer, sink: sink}
}

func (f fixture) client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(f.proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test server certificate
	}}
}

var testResolver = fakeResolver{
	"app.test":    {"203.0.113.10"},
	"rebind.test": {"127.0.0.1"},
	"mixed.test":  {"203.0.113.10", "169.254.169.254"},
	"evil.test":   {"203.0.113.66"},
}

func helloServer(t *testing.T, useTLS bool) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.Host)
	})
	var s *httptest.Server
	if useTLS {
		s = httptest.NewTLSServer(handler)
	} else {
		s = httptest.NewServer(handler)
	}
	t.Cleanup(s.Close)
	return s
}

func get(t *testing.T, c *http.Client, rawURL string) (int, string) {
	t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func lastEvent(t *testing.T, sink *MemorySink) Event {
	t.Helper()
	events := sink.Events()
	if len(events) == 0 {
		t.Fatal("no audit event was recorded")
	}
	return events[len(events)-1]
}

func TestProxyForwardsInScopeHTTPToThePinnedAddress(t *testing.T) {
	upstream := helloServer(t, false)
	f := newFixture(t, upstream.Listener.Addr().String(), testResolver)

	status, body := get(t, f.client(), "http://app.test/hello")

	if status != http.StatusOK || body != "hello from app.test" {
		t.Fatalf("got %d %q", status, body)
	}
	if got := f.dialer.addresses(); len(got) != 1 || got[0] != "203.0.113.10:80" {
		t.Fatalf("dialed %v; want the resolved address, not the name", got)
	}
	if e := lastEvent(t, f.sink); !e.Allowed || e.Target != "app.test:80" {
		t.Fatalf("audit event = %+v", e)
	}
}

func TestProxyBlocksOutOfScopeRequests(t *testing.T) {
	upstream := helloServer(t, false)
	cases := map[string]string{
		"unlisted host":                    "http://evil.test/",
		"name resolving to loopback":       "http://rebind.test/",
		"one of several answers is unsafe": "http://mixed.test/",
		"port outside scope":               "http://app.test:8080/",
		"address literal":                  "http://203.0.113.10/",
		"metadata address":                 "http://169.254.169.254/latest/meta-data/",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, upstream.Listener.Addr().String(), testResolver)

			status, body := get(t, f.client(), target)

			if status != http.StatusForbidden {
				t.Fatalf("got %d %q; want 403", status, body)
			}
			if got := f.dialer.addresses(); len(got) != 0 {
				t.Fatalf("a connection was opened to %v", got)
			}
			if e := lastEvent(t, f.sink); e.Allowed || e.Reason == "" {
				t.Fatalf("audit event = %+v; want a denial with a reason", e)
			}
		})
	}
}

func TestProxyTunnelsInScopeHTTPS(t *testing.T) {
	upstream := helloServer(t, true)
	f := newFixture(t, upstream.Listener.Addr().String(), testResolver)

	status, body := get(t, f.client(), "https://app.test/")

	if status != http.StatusOK || body != "hello from app.test" {
		t.Fatalf("got %d %q", status, body)
	}
	if got := f.dialer.addresses(); len(got) != 1 || got[0] != "203.0.113.10:443" {
		t.Fatalf("dialed %v", got)
	}
	if e := lastEvent(t, f.sink); !e.Allowed || e.Method != http.MethodConnect {
		t.Fatalf("audit event = %+v", e)
	}
}

func TestProxyRefusesOutOfScopeTunnel(t *testing.T) {
	upstream := helloServer(t, true)
	f := newFixture(t, upstream.Listener.Addr().String(), testResolver)

	conn, err := net.Dial("tcp", f.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", resp.StatusCode)
	}
	if got := f.dialer.addresses(); len(got) != 0 {
		t.Fatalf("a connection was opened to %v", got)
	}
}

func TestProxyReportsUnreachableUpstreamAsBadGateway(t *testing.T) {
	f := newFixture(t, "127.0.0.1:1", testResolver)
	f.dialer.err = errors.New("connection refused")

	status, _ := get(t, f.client(), "http://app.test/")

	if status != http.StatusBadGateway {
		t.Fatalf("status = %d; want 502", status)
	}
	if e := lastEvent(t, f.sink); e.Allowed {
		t.Fatalf("audit event = %+v; want not allowed", e)
	}
}

func TestProxyRejectsNonProxyRequests(t *testing.T) {
	f := newFixture(t, "127.0.0.1:1", testResolver)

	resp, err := http.Get(f.proxyURL.String() + "/not-a-proxy-request")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", resp.StatusCode)
	}
}

func TestProxyDoesNotForwardHopHeaders(t *testing.T) {
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	defer upstream.Close()
	f := newFixture(t, upstream.Listener.Addr().String(), testResolver)

	req, _ := http.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("X-Kept", "yes")
	resp, err := f.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seen.Get("Proxy-Authorization") != "" {
		t.Fatal("Proxy-Authorization reached the target")
	}
	if seen.Get("X-Kept") != "yes" {
		t.Fatal("an ordinary header was dropped")
	}
}

func TestGuardRejectsMalformedAddresses(t *testing.T) {
	policy, _ := scope.New(scope.Config{Hosts: []string{"app.test"}})
	guard, err := NewGuard(policy, testResolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"app.test", "app.test:notaport", "app.test:0", "app.test:99999"} {
		if _, err := guard.DialContext(context.Background(), "tcp", address); !scope.IsDenied(err) {
			t.Errorf("DialContext(%q) = %v; want a denial", address, err)
		}
		if err := guard.CheckTarget(address); !scope.IsDenied(err) {
			t.Errorf("CheckTarget(%q) = %v; want a denial", address, err)
		}
	}
}

func TestGuardFailsWhenANameDoesNotResolve(t *testing.T) {
	policy, _ := scope.New(scope.Config{Hosts: []string{"app.test", "empty.test"}})
	guard, _ := NewGuard(policy, fakeResolver{"empty.test": {}}, nil)
	for _, address := range []string{"app.test:443", "empty.test:443"} {
		_, err := guard.DialContext(context.Background(), "tcp", address)
		if err == nil || scope.IsDenied(err) {
			t.Errorf("DialContext(%q) = %v; want a resolution error", address, err)
		}
	}
}

func TestConstructorsRequireTheirDependencies(t *testing.T) {
	if _, err := NewGuard(nil, nil, nil); err == nil {
		t.Error("NewGuard accepted a nil policy")
	}
	policy, _ := scope.New(scope.Config{Hosts: []string{"app.test"}})
	guard, _ := NewGuard(policy, nil, nil)
	if _, err := NewProxy(nil, &MemorySink{}); err == nil {
		t.Error("NewProxy accepted a nil guard")
	}
	if _, err := NewProxy(guard, nil); err == nil {
		t.Error("NewProxy accepted a nil sink")
	}
}

func TestJSONLSinkWritesOneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONLSink(&buf)

	sink.Record(Event{Method: "GET", Target: "app.test:80", Allowed: true})
	sink.Record(Event{Method: "CONNECT", Target: "evil.test:443", Reason: "host is not in scope"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("wrote %d lines; want 2: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[1], `"allowed":false`) || !strings.Contains(lines[1], "evil.test:443") {
		t.Fatalf("second line = %s", lines[1])
	}
}
