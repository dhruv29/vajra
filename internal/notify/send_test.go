package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// secretPath stands for the token a real webhook URL carries. No error may
// repeat any part of it.
const secretPath = "/services/T000/B000/s3cr3t-token?key=s3cr3t-query"

var leaks = []string{"s3cr3t", "/services", "T000", "key="}

func assertNoLeak(t *testing.T, err error, extra ...string) {
	t.Helper()
	for _, secret := range append(append([]string(nil), leaks...), extra...) {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks %q: %v", secret, err)
		}
	}
}

var sample = Summary{
	RunID: "20261121-195440-0a1b2c3d", Targets: []string{"https://app.test"},
	Confirmed: 2, Unconfirmed: 1, Refuted: 4, OutOfScope: 3,
	TopFindings: []TopFinding{{Title: "SQL injection", Severity: "high", Score: 80, Target: "https://app.test/login"}},
}

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

// recordingDialer notes every address the guard chose to connect to. With a
// non-empty "to" it connects to that local address instead, standing in for
// the real network; otherwise every dial fails.
type recordingDialer struct {
	mu     sync.Mutex
	dialed []string
	to     string
}

func (d *recordingDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	if d.to == "" {
		return nil, errors.New("connection refused")
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.to)
}

func (d *recordingDialer) addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// received is what a test webhook saw.
type received struct {
	method      string
	path        string
	contentType string
	body        []byte
}

// webhook starts a plain-HTTP server that answers with status and records
// the requests it gets.
func webhook(t *testing.T, status int, reply string) (*httptest.Server, func() []received) {
	t.Helper()
	var mu sync.Mutex
	var got []received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, received{r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), body})
		mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []received {
		mu.Lock()
		defer mu.Unlock()
		return append([]received(nil), got...)
	}
}

func hostPort(t *testing.T, rawURL string) (host, port string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), u.Port()
}

func TestSendPostsTheSummaryAsJSONToAnInternalWebhookWhenPrivateIsAllowed(t *testing.T) {
	srv, requests := webhook(t, http.StatusOK, "ok")

	err := Send(context.Background(), sample, Options{URL: srv.URL + secretPath, AllowPrivate: true})

	if err != nil {
		t.Fatal(err)
	}
	got := requests()
	if len(got) != 1 {
		t.Fatalf("webhook got %d requests; want 1", len(got))
	}
	if got[0].method != http.MethodPost || got[0].path != secretPath || got[0].contentType != "application/json" {
		t.Errorf("request = %s %s (%s)", got[0].method, got[0].path, got[0].contentType)
	}
	var sent Summary
	if err := json.Unmarshal(got[0].body, &sent); err != nil || !reflect.DeepEqual(sent, sample) {
		t.Errorf("body = %s, err = %v; want the summary", got[0].body, err)
	}
}

func TestSendResolvesANameThroughTheConfiguredResolver(t *testing.T) {
	srv, requests := webhook(t, http.StatusNoContent, "")
	_, port := hostPort(t, srv.URL)
	resolver := fakeResolver{"chat.internal": {"127.0.0.1"}}

	err := Send(context.Background(), sample, Options{
		URL: "http://chat.internal:" + port + secretPath, Resolver: resolver, AllowPrivate: true,
	})

	if err != nil || len(requests()) != 1 {
		t.Fatalf("err = %v, requests = %d; want one delivered request", err, len(requests()))
	}
}

func TestSendTreatsEveryNon2xxReplyAsAnErrorWithoutLeaking(t *testing.T) {
	const replyBody = "invalid_token: s3cr3t-token is revoked, reply-body-marker"
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusNotModified} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv, _ := webhook(t, status, replyBody)

			err := Send(context.Background(), sample, Options{URL: srv.URL + secretPath, AllowPrivate: true})

			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("err = %v; want an error naming status %d", err, status)
			}
			if !strings.Contains(err.Error(), srv.URL) {
				t.Errorf("error should name scheme and host %s: %v", srv.URL, err)
			}
			assertNoLeak(t, err, "reply-body-marker", "revoked")
		})
	}
}

func TestSendNeverFollowsARedirect(t *testing.T) {
	elsewhere, elsewhereRequests := webhook(t, http.StatusOK, "ok")
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/landing-marker", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)
	tests := []struct {
		name string
		opts Options
	}{
		{"guarded client", Options{AllowPrivate: true}},
		{"client supplied by the caller", Options{HTTP: &http.Client{}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.URL = redirector.URL + secretPath
			opts.AllowPrivate = true

			err := Send(context.Background(), sample, opts)

			if err == nil || !strings.Contains(err.Error(), "redirect") || !strings.Contains(err.Error(), "307") {
				t.Fatalf("err = %v; want a redirect error naming status 307", err)
			}
			if n := len(elsewhereRequests()); n != 0 {
				t.Fatalf("the redirect target got %d requests; want 0", n)
			}
			assertNoLeak(t, err, "landing-marker", elsewhere.URL)
			if opts.HTTP != nil && opts.HTTP.CheckRedirect != nil {
				t.Error("the caller's client was modified")
			}
		})
	}
}

func TestSendRefusesUnacceptableURLsBeforeAnyRequest(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		allowPrivate bool
		want         string
	}{
		{"plain http without AllowPrivate", "http://hooks.example" + secretPath, false, "must use https"},
		{"user name and password", "https://bot:hunter2@hooks.example" + secretPath, false, "user name or password"},
		{"user name only", "https://bot@hooks.example" + secretPath, true, "user name or password"},
		{"another scheme", "ftp://hooks.example" + secretPath, true, "not supported"},
		{"no scheme", "hooks.example" + secretPath, true, "no host"},
		{"no host", "https://" + secretPath, false, "no host"},
		{"empty", "", false, "no host"},
		{"unparseable", "https://hooks.example/%zz" + secretPath, false, "malformed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &recordingDialer{}
			client := &http.Client{Transport: &http.Transport{DialContext: dialer.dial}}

			err := Send(context.Background(), sample, Options{URL: tc.url, HTTP: client, AllowPrivate: tc.allowPrivate})

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want it to mention %q", err, tc.want)
			}
			if dialed := dialer.addresses(); len(dialed) != 0 {
				t.Fatalf("a connection was attempted to %v", dialed)
			}
			assertNoLeak(t, err, "hunter2", "bot")
		})
	}
}

func TestGuardRefusesNamesThatResolveToNonPublicAddressesWithoutDialing(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		answers []string
	}{
		{"loopback", "hooks.example", []string{"127.0.0.1"}},
		{"loopback, high in the range", "hooks.example", []string{"127.8.8.8"}},
		{"IPv6 loopback", "hooks.example", []string{"::1"}},
		{"cloud metadata", "hooks.example", []string{"169.254.169.254"}},
		{"link-local", "hooks.example", []string{"169.254.10.1"}},
		{"IPv6 link-local with a zone", "hooks.example", []string{"fe80::1%eth0"}},
		{"private 10/8", "hooks.example", []string{"10.1.2.3"}},
		{"private 172.16/12", "hooks.example", []string{"172.31.255.254"}},
		{"private 192.168/16", "hooks.example", []string{"192.168.1.10"}},
		{"unique local", "hooks.example", []string{"fd12:3456::1"}},
		{"carrier-grade NAT", "hooks.example", []string{"100.64.0.1"}},
		{"unspecified", "hooks.example", []string{"0.0.0.0"}},
		{"IPv6 unspecified", "hooks.example", []string{"::"}},
		{"multicast", "hooks.example", []string{"224.0.0.251"}},
		{"IPv6 multicast", "hooks.example", []string{"ff02::1"}},
		{"IPv4-mapped loopback", "hooks.example", []string{"::ffff:127.0.0.1"}},
		{"IPv4-mapped metadata", "hooks.example", []string{"::ffff:169.254.169.254"}},
		{"NAT64 form of metadata", "hooks.example", []string{"64:ff9b::a9fe:a9fe"}},
		{"public first, private second", "hooks.example", []string{"93.184.216.34", "10.0.0.5"}},
		{"private first, public second", "hooks.example", []string{"192.168.0.1", "93.184.216.34"}},
		{"public IPv6 with metadata", "hooks.example", []string{"2606:2800:220:1::1", "169.254.169.254"}},
		{"literal loopback address", "127.0.0.1", nil},
		{"literal metadata address", "169.254.169.254", nil},
		{"literal IPv6 loopback", "::1", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &recordingDialer{}
			g := &guard{resolver: fakeResolver{tc.host: tc.answers}, dial: dialer.dial}

			conn, err := g.dialContext(context.Background(), "tcp", net.JoinHostPort(tc.host, "443"))

			if err == nil {
				conn.Close()
				t.Fatal("the guard connected")
			}
			if !strings.Contains(err.Error(), "not a public address") {
				t.Fatalf("err = %v; want a non-public refusal", err)
			}
			if dialed := dialer.addresses(); len(dialed) != 0 {
				t.Fatalf("a connection was attempted to %v", dialed)
			}
		})
	}
}

func TestGuardDialsTheCheckedAddressNotTheName(t *testing.T) {
	srv, _ := webhook(t, http.StatusOK, "ok")
	dialer := &recordingDialer{to: srv.Listener.Addr().String()}
	g := &guard{resolver: fakeResolver{"hooks.example": {"::ffff:93.184.216.34"}}, dial: dialer.dial}

	conn, err := g.dialContext(context.Background(), "tcp", "hooks.example:443")

	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got, want := dialer.addresses(), []string{"93.184.216.34:443"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dialed %v; want %v", got, want)
	}
}

func TestGuardTriesEachCheckedAddressAndReportsTheLastFailure(t *testing.T) {
	dialer := &recordingDialer{}
	g := &guard{resolver: fakeResolver{"hooks.example": {"93.184.216.34", "2606:2800:220:1::1"}}, dial: dialer.dial}

	_, err := g.dialContext(context.Background(), "tcp", "hooks.example:8443")

	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v; want the dial failure", err)
	}
	want := []string{"93.184.216.34:8443", "[2606:2800:220:1::1]:8443"}
	if got := dialer.addresses(); !reflect.DeepEqual(got, want) {
		t.Fatalf("dialed %v; want %v", got, want)
	}
}

func TestGuardRejectsWhatItCannotResolveOrParse(t *testing.T) {
	tests := []struct {
		name     string
		resolver fakeResolver
		address  string
		want     string
	}{
		{"unknown name", fakeResolver{}, "hooks.example:443", "no such host"},
		{"name with no addresses", fakeResolver{"hooks.example": nil}, "hooks.example:443", "no addresses"},
		{"address without a port", fakeResolver{}, "hooks.example", "malformed address"},
		{"port zero", fakeResolver{}, "hooks.example:0", "malformed port"},
		{"port that is not a number", fakeResolver{}, "hooks.example:https", "malformed port"},
		{"port out of range", fakeResolver{}, "hooks.example:70000", "malformed port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &recordingDialer{}
			g := &guard{resolver: tc.resolver, dial: dialer.dial}

			_, err := g.dialContext(context.Background(), "tcp", tc.address)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want it to mention %q", err, tc.want)
			}
			if dialed := dialer.addresses(); len(dialed) != 0 {
				t.Fatalf("a connection was attempted to %v", dialed)
			}
		})
	}
}

func TestIsPublicAcceptsOrdinaryInternetAddresses(t *testing.T) {
	for _, raw := range []string{"93.184.216.34", "1.1.1.1", "172.15.255.255", "172.32.0.1", "100.63.255.255", "2606:2800:220:1::1"} {
		if !isPublic(netip.MustParseAddr(raw)) {
			t.Errorf("%s was judged non-public", raw)
		}
	}
	if isPublic(netip.Addr{}) {
		t.Error("the zero address was judged public")
	}
}

// connCounter counts connections a server accepted, whether or not a request
// followed.
func connCounter(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepted atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &accepted
}

func TestSendRefusesAWebhookThatResolvesInwardAndNeverConnects(t *testing.T) {
	tests := []struct {
		name    string
		answers []string
	}{
		{"loopback", []string{"127.0.0.1"}},
		{"public and loopback mixed", []string{"93.184.216.34", "127.0.0.1"}},
		{"private", []string{"10.0.0.5"}},
		{"cloud metadata", []string{"169.254.169.254"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, accepted := connCounter(t)
			_, port := hostPort(t, srv.URL)
			resolver := fakeResolver{"hooks.example": tc.answers}

			err := Send(context.Background(), sample, Options{
				URL: "https://hooks.example:" + port + secretPath, Resolver: resolver,
			})

			if err == nil || !strings.Contains(err.Error(), "not a public address") {
				t.Fatalf("err = %v; want a non-public refusal", err)
			}
			if n := accepted.Load(); n != 0 {
				t.Fatalf("the local server accepted %d connections; want 0", n)
			}
			assertNoLeak(t, err)
		})
	}
}

func TestSendRefusesALiteralLoopbackURLByDefault(t *testing.T) {
	srv, accepted := connCounter(t)

	err := Send(context.Background(), sample, Options{URL: srv.URL + secretPath})

	if err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("err = %v; want a non-public refusal", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the local server accepted %d connections; want 0", n)
	}
}

func TestGuardedClientHasNoProxyAndRefusesRedirects(t *testing.T) {
	client := guardedClient(&guard{})

	transport, ok := client.Transport.(*http.Transport)

	if !ok || transport.Proxy != nil || transport.DialContext == nil {
		t.Fatalf("transport = %+v; want a guarded transport with no proxy", client.Transport)
	}
	if client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("the client would follow redirects")
	}
	if client.Timeout != sendTimeout {
		t.Fatalf("timeout = %v; want %v", client.Timeout, sendTimeout)
	}
}

func TestSendIgnoresAProxyFromTheEnvironment(t *testing.T) {
	proxy, proxyRequests := webhook(t, http.StatusOK, "from the proxy")
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	srv, requests := webhook(t, http.StatusOK, "ok")
	_, port := hostPort(t, srv.URL)

	err := Send(context.Background(), sample, Options{
		URL: "http://chat.internal:" + port + "/hook", Resolver: fakeResolver{"chat.internal": {"127.0.0.1"}}, AllowPrivate: true,
	})

	if err != nil || len(requests()) != 1 || len(proxyRequests()) != 0 {
		t.Fatalf("err = %v, direct requests = %d, proxied requests = %d; want 1 direct and 0 proxied",
			err, len(requests()), len(proxyRequests()))
	}
}

func TestSendStopsWhenTheContextIsCancelled(t *testing.T) {
	arrived := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(arrived)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-arrived
		cancel()
	}()

	err := Send(ctx, sample, Options{URL: srv.URL + secretPath, AllowPrivate: true})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
	assertNoLeak(t, err)
}

func TestSendDoesNothingWhenTheContextIsAlreadyCancelled(t *testing.T) {
	srv, requests := webhook(t, http.StatusOK, "ok")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Send(ctx, sample, Options{URL: srv.URL + secretPath, AllowPrivate: true})

	if !errors.Is(err, context.Canceled) || len(requests()) != 0 {
		t.Fatalf("err = %v, requests = %d; want context.Canceled and no request", err, len(requests()))
	}
}

func TestSendReportsAConnectionFailureWithoutTheURLPath(t *testing.T) {
	srv, _ := webhook(t, http.StatusOK, "ok")
	closedURL := srv.URL
	srv.Close()

	err := Send(context.Background(), sample, Options{URL: closedURL + secretPath, AllowPrivate: true})

	if err == nil || !strings.Contains(err.Error(), closedURL) {
		t.Fatalf("err = %v; want a failure naming %s", err, closedURL)
	}
	assertNoLeak(t, err)
}
