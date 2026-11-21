package egress

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/scope"
)

const (
	socksTestDeadline = 5 * time.Second
	socksReplyBytes   = 10
)

type socksFixture struct {
	addr   string
	dialer *redirectDialer
	sink   *MemorySink
	cancel context.CancelFunc
	// done is closed when Serve returns; serveErr is then what it returned.
	done     chan struct{}
	serveErr *error
}

// newSOCKSFixture starts a SOCKS5 gate whose guard connects to upstream
// instead of the real network. configure may adjust the server before it
// starts serving.
func newSOCKSFixture(t *testing.T, upstream string, sink Sink, configure func(*SOCKS5)) socksFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveSOCKS(t, upstream, sink, configure, listener)
}

// serveSOCKS is newSOCKSFixture with the listener given, so a test can put a
// fake one in front of the real socket.
func serveSOCKS(t *testing.T, upstream string, sink Sink, configure func(*SOCKS5), listener net.Listener) socksFixture {
	t.Helper()
	policy, err := scope.New(scope.Config{
		Hosts: []string{"app.test", "rebind.test", "mixed.test"},
		CIDRs: []string{"2001:db8::/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &redirectDialer{to: upstream}
	guard, err := NewGuard(policy, testResolver, dialer.dial)
	if err != nil {
		t.Fatal(err)
	}
	memory := &MemorySink{}
	if sink == nil {
		sink = memory
	}
	server, err := NewSOCKS5(guard, sink)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(server)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, serveErr := make(chan struct{}), new(error)
	go func() {
		defer close(done)
		*serveErr = server.Serve(ctx, listener)
	}()
	f := socksFixture{addr: listener.Addr().String(), dialer: dialer, sink: memory, cancel: cancel, done: done, serveErr: serveErr}
	t.Cleanup(func() {
		cancel()
		f.stopped(t)
	})
	return f
}

// stopped waits for Serve to return and gives back its result.
func (f socksFixture) stopped(t *testing.T) error {
	t.Helper()
	select {
	case <-f.done:
		return *f.serveErr
	case <-time.After(socksTestDeadline):
		t.Fatal("Serve did not return; an open connection is holding it")
		return nil
	}
}

// echoServer answers every connection with whatever it is sent.
func echoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		listener.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			})
		}
	})
	return listener.Addr().String()
}

func (f socksFixture) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(socksTestDeadline))
	return conn
}

// greet offers "no authentication" and requires the gate to choose it.
func greet(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil || choice != [2]byte{0x05, 0x00} {
		t.Fatalf("method selection = % x, err = %v; want 05 00", choice, err)
	}
}

func withPort(request []byte, port uint16) []byte {
	return binary.BigEndian.AppendUint16(request, port)
}

func domainRequest(command byte, host string, port uint16) []byte {
	request := append([]byte{0x05, command, 0x00, 0x03, byte(len(host))}, host...)
	return withPort(request, port)
}

func addrRequest(address string, port uint16) []byte {
	addr := netip.MustParseAddr(address)
	addressType := byte(0x01)
	if addr.Is6() {
		addressType = 0x04
	}
	return withPort(append([]byte{0x05, 0x01, 0x00, addressType}, addr.AsSlice()...), port)
}

// replyCode sends a request and returns the reply code, requiring the reply
// to be well formed and to name no bound address.
func replyCode(t *testing.T, conn net.Conn, request []byte) byte {
	t.Helper()
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, socksReplyBytes)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	want := []byte{0x05, reply[1], 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply = % x; want % x", reply, want)
	}
	return reply[1]
}

// expectClosed requires the gate to have closed the connection without
// sending anything further.
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	var one [1]byte
	n, err := conn.Read(one[:])
	var timeout net.Error
	if n != 0 || err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("read %d byte(s), err = %v; want the connection closed by the gate", n, err)
	}
}

func TestSOCKS5RelaysInScopeDomainToThePinnedAddress(t *testing.T) {
	f := newSOCKSFixture(t, echoServer(t), nil, nil)
	conn := f.dial(t)
	greet(t, conn)

	code := replyCode(t, conn, domainRequest(0x01, "app.test", 443))

	if code != 0x00 {
		t.Fatalf("reply code = %#02x; want success", code)
	}
	if e := lastEvent(t, f.sink); !e.Allowed || e.Outcome != Allowed || e.Method != "SOCKS5" || e.Target != "app.test:443" || e.Time.IsZero() {
		t.Fatalf("audit event = %+v; the decision must be logged before the success reply", e)
	}
	for _, message := range []string{"first message", "second message"} {
		if _, err := conn.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}
		echoed := make([]byte, len(message))
		if _, err := io.ReadFull(conn, echoed); err != nil || string(echoed) != message {
			t.Fatalf("echoed %q, err = %v; want %q", echoed, err, message)
		}
	}
	if got := f.dialer.addresses(); len(got) != 1 || got[0] != "203.0.113.10:443" {
		t.Fatalf("dialed %v; want the resolved address, not the name", got)
	}
}

func TestSOCKS5RefusesTargetsOutsideThePolicy(t *testing.T) {
	cases := []struct {
		name    string
		request []byte
		target  string
	}{
		{"unlisted domain", domainRequest(0x01, "evil.test", 443), "evil.test:443"},
		{"domain resolving to loopback", domainRequest(0x01, "rebind.test", 443), "rebind.test:443"},
		{"one of several answers is unsafe", domainRequest(0x01, "mixed.test", 443), "mixed.test:443"},
		{"port outside scope", domainRequest(0x01, "app.test", 8080), "app.test:8080"},
		{"port zero", domainRequest(0x01, "app.test", 0), "app.test:0"},
		{"loopback IPv4 literal", addrRequest("127.0.0.1", 443), "127.0.0.1:443"},
		{"metadata IPv4 literal", addrRequest("169.254.169.254", 80), "169.254.169.254:80"},
		{"unlisted IPv4 literal", addrRequest("203.0.113.10", 443), "203.0.113.10:443"},
		{"loopback IPv6 literal", addrRequest("::1", 443), "[::1]:443"},
		{"IPv4-mapped loopback", addrRequest("::ffff:127.0.0.1", 443), "[::ffff:127.0.0.1]:443"},
		{"address literal sent as a domain", domainRequest(0x01, "127.0.0.1", 443), "127.0.0.1:443"},
		{"domain that is not a host name", domainRequest(0x01, "app.test:443]", 443), "[app.test:443]]:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSOCKSFixture(t, echoServer(t), nil, nil)
			conn := f.dial(t)
			greet(t, conn)

			code := replyCode(t, conn, tc.request)

			if code != 0x02 {
				t.Fatalf("reply code = %#02x; want 0x02, not allowed by ruleset", code)
			}
			if got := f.dialer.addresses(); len(got) != 0 {
				t.Fatalf("a connection was opened to %v", got)
			}
			e := lastEvent(t, f.sink)
			if e.Allowed || e.Outcome != Denied || e.Reason == "" || e.Method != "SOCKS5" || e.Target != tc.target {
				t.Fatalf("audit event = %+v; want a denial of %s with a reason", e, tc.target)
			}
			expectClosed(t, conn)
		})
	}
}

func TestSOCKS5ParsesAnIPv6Target(t *testing.T) {
	f := newSOCKSFixture(t, echoServer(t), nil, nil)
	conn := f.dial(t)
	greet(t, conn)

	code := replyCode(t, conn, addrRequest("2001:db8::10", 443))

	if code != 0x00 {
		t.Fatalf("reply code = %#02x; want success for an address inside a scoped CIDR", code)
	}
	if got := f.dialer.addresses(); len(got) != 1 || got[0] != "[2001:db8::10]:443" {
		t.Fatalf("dialed %v", got)
	}
	if e := lastEvent(t, f.sink); e.Outcome != Allowed || e.Target != "[2001:db8::10]:443" {
		t.Fatalf("audit event = %+v", e)
	}
}

func TestSOCKS5RejectsRequestsItDoesNotSupport(t *testing.T) {
	cases := []struct {
		name    string
		request []byte
		want    byte
	}{
		{"BIND", domainRequest(0x02, "app.test", 443), 0x07},
		{"UDP ASSOCIATE", domainRequest(0x03, "app.test", 443), 0x07},
		{"unknown command", domainRequest(0x09, "app.test", 443), 0x07},
		{"unknown command and address type", []byte{0x05, 0x02, 0x00, 0x05}, 0x07},
		{"unknown address type", []byte{0x05, 0x01, 0x00, 0x05}, 0x08},
		{"address type zero", []byte{0x05, 0x01, 0x00, 0x00}, 0x08},
		{"non-zero reserved byte", []byte{0x05, 0x01, 0x01, 0x03, 8, 'a', 'p', 'p', '.', 't', 'e', 's', 't', 0x01, 0xBB}, 0x01},
		{"empty domain", domainRequest(0x01, "", 443), 0x01},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSOCKSFixture(t, echoServer(t), nil, nil)
			conn := f.dial(t)
			greet(t, conn)

			code := replyCode(t, conn, tc.request)

			if code != tc.want {
				t.Fatalf("reply code = %#02x; want %#02x", code, tc.want)
			}
			if got := f.dialer.addresses(); len(got) != 0 {
				t.Fatalf("a connection was opened to %v", got)
			}
			expectClosed(t, conn)
		})
	}
}

func TestSOCKS5ClosesClientsSpeakingAnotherVersion(t *testing.T) {
	cases := map[string]func(t *testing.T, conn net.Conn){
		"greeting": func(t *testing.T, conn net.Conn) {
			_, _ = conn.Write([]byte{0x04, 0x01, 0x00})
		},
		"request": func(t *testing.T, conn net.Conn) {
			greet(t, conn)
			_, _ = conn.Write([]byte{0x04, 0x01, 0x00, 0x01})
		},
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSOCKSFixture(t, echoServer(t), nil, nil)
			conn := f.dial(t)

			send(t, conn)

			expectClosed(t, conn)
			if got := f.dialer.addresses(); len(got) != 0 {
				t.Fatalf("a connection was opened to %v", got)
			}
		})
	}
}

func TestSOCKS5RefusesClientsThatDoNotOfferNoAuth(t *testing.T) {
	cases := map[string][]byte{
		"username and password only": {0x05, 0x01, 0x02},
		"GSSAPI and password":        {0x05, 0x02, 0x01, 0x02},
		"no methods at all":          {0x05, 0x00},
	}
	for name, greeting := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSOCKSFixture(t, echoServer(t), nil, nil)
			conn := f.dial(t)

			if _, err := conn.Write(greeting); err != nil {
				t.Fatal(err)
			}
			var choice [2]byte
			_, err := io.ReadFull(conn, choice[:])

			if err != nil || choice != [2]byte{0x05, 0xFF} {
				t.Fatalf("method selection = % x, err = %v; want 05 ff", choice, err)
			}
			expectClosed(t, conn)
		})
	}
}

func TestSOCKS5ReportsAnUnreachableUpstream(t *testing.T) {
	cases := []struct {
		name    string
		request []byte
		dialErr error
		want    byte
	}{
		{"refused connection", domainRequest(0x01, "app.test", 443), fmt.Errorf("connect: %w", syscall.ECONNREFUSED), 0x05},
		{"no route", domainRequest(0x01, "app.test", 443), errors.New("no route to host"), 0x04},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSOCKSFixture(t, "127.0.0.1:1", nil, nil)
			f.dialer.err = tc.dialErr
			conn := f.dial(t)
			greet(t, conn)

			code := replyCode(t, conn, tc.request)

			if code != tc.want {
				t.Fatalf("reply code = %#02x; want %#02x", code, tc.want)
			}
			if e := lastEvent(t, f.sink); !e.Allowed || e.Outcome != Failed || e.Reason == "" || e.Method != "SOCKS5" {
				t.Fatalf("audit event = %+v; an unreachable target was allowed by policy but failed", e)
			}
			expectClosed(t, conn)
		})
	}
}

// byteCounter is an upstream that counts what reaches it.
type byteCounter struct {
	mu       sync.Mutex
	received int
}

func (b *byteCounter) serve(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		listener.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				n, _ := io.Copy(io.Discard, conn)
				b.mu.Lock()
				b.received += int(n)
				b.mu.Unlock()
			})
		}
	})
	return listener.Addr().String()
}

func (b *byteCounter) total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.received
}

func TestSOCKS5RelaysNothingWhenTheAuditLogCannotBeWritten(t *testing.T) {
	upstream := &byteCounter{}
	f := newSOCKSFixture(t, upstream.serve(t), brokenSink{}, nil)
	conn := f.dial(t)
	greet(t, conn)

	code := replyCode(t, conn, domainRequest(0x01, "app.test", 443))
	_, _ = conn.Write([]byte("must not be relayed"))

	if code == 0x00 {
		t.Fatal("the gate reported success for a connection it could not audit")
	}
	expectClosed(t, conn)
	f.cancel()
	f.stopped(t) // every connection has finished, so the count below is final
	if got := upstream.total(); got != 0 {
		t.Fatalf("%d byte(s) reached the target unaudited", got)
	}
}

func TestSOCKS5DisconnectsAClientThatStallsMidHandshake(t *testing.T) {
	stalls := map[string][]byte{
		"before the greeting":      nil,
		"inside the greeting":      {0x05, 0x02, 0x00},
		"before the request":       {0x05, 0x01, 0x00},
		"inside the request":       {0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x08, 'a', 'p'},
		"inside a refused command": {0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x03, 0x08, 'a', 'p'},
	}
	for name, sent := range stalls {
		t.Run(name, func(t *testing.T) {
			f := newSOCKSFixture(t, echoServer(t), nil, func(s *SOCKS5) {
				s.handshakeTimeout = 150 * time.Millisecond
			})
			conn := f.dial(t)
			if _, err := conn.Write(sent); err != nil {
				t.Fatal(err)
			}

			started := time.Now()
			_, err := io.Copy(io.Discard, conn) // returns when the gate closes

			if err != nil || time.Since(started) > 4*time.Second {
				t.Fatalf("the stalled connection was still open after %v (err = %v)", time.Since(started), err)
			}
			if got := f.dialer.addresses(); len(got) != 0 {
				t.Fatalf("a connection was opened to %v", got)
			}
		})
	}
}

func TestSOCKS5ClosesAnIdleTunnel(t *testing.T) {
	upstream := &byteCounter{} // accepts and says nothing
	f := newSOCKSFixture(t, upstream.serve(t), nil, func(s *SOCKS5) {
		s.tunnelIdle = 150 * time.Millisecond
	})
	conn := f.dial(t)
	greet(t, conn)
	if code := replyCode(t, conn, domainRequest(0x01, "app.test", 443)); code != 0x00 {
		t.Fatalf("reply code = %#02x; want success", code)
	}

	started := time.Now()
	_, err := io.Copy(io.Discard, conn)

	if err != nil || time.Since(started) > 4*time.Second {
		t.Fatalf("the idle tunnel was still open after %v (err = %v)", time.Since(started), err)
	}
}

func TestSOCKS5ServeStopsCleanlyAndClosesOpenConnectionsOnCancel(t *testing.T) {
	f := newSOCKSFixture(t, echoServer(t), nil, nil)
	tunnelled := f.dial(t)
	greet(t, tunnelled)
	if code := replyCode(t, tunnelled, domainRequest(0x01, "app.test", 443)); code != 0x00 {
		t.Fatalf("reply code = %#02x; want success", code)
	}
	handshaking := f.dial(t)
	greet(t, handshaking)

	f.cancel()

	if err := f.stopped(t); err != nil {
		t.Fatalf("Serve = %v; want nil after its context was cancelled", err)
	}
	expectClosed(t, tunnelled)
	expectClosed(t, handshaking)
	if conn, err := net.DialTimeout("tcp", f.addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("the listener still accepts connections after Serve returned")
	}
}

func TestSOCKS5ServeReturnsNilWhenTheListenerIsClosed(t *testing.T) {
	policy, _ := scope.New(scope.Config{Hosts: []string{"app.test"}})
	guard, _ := NewGuard(policy, testResolver, nil)
	server, _ := NewSOCKS5(guard, &MemorySink{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), listener) }()

	listener.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v; want nil", err)
		}
	case <-time.After(socksTestDeadline):
		t.Fatal("Serve did not return after its listener was closed")
	}
}

// failingListener hands out one connection and then fails, like a listener
// whose socket has broken.
type failingListener struct {
	net.Listener
	mu     sync.Mutex
	served bool
	err    error
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	served := l.served
	l.served = true
	l.mu.Unlock()
	if served {
		return nil, l.err
	}
	return l.Listener.Accept()
}

func TestSOCKS5ServeReportsAnAcceptFailureAndLeavesNoConnectionBehind(t *testing.T) {
	policy, _ := scope.New(scope.Config{Hosts: []string{"app.test"}})
	guard, _ := NewGuard(policy, testResolver, nil)
	server, _ := NewSOCKS5(guard, &MemorySink{})
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	broken := errors.New("too many open files")
	client, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(socksTestDeadline))

	err = server.Serve(context.Background(), &failingListener{Listener: inner, err: broken})

	if !errors.Is(err, broken) {
		t.Fatalf("Serve = %v; want the accept error", err)
	}
	expectClosed(t, client)
}

func TestSOCKS5DropsConnectionsAcceptedDuringShutdown(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	open := &connSet{conns: map[net.Conn]struct{}{}}

	open.closeAll()

	if open.add(a) {
		t.Fatal("a closed set accepted a connection it would never close")
	}
}

func TestNewSOCKS5RequiresItsDependencies(t *testing.T) {
	policy, _ := scope.New(scope.Config{Hosts: []string{"app.test"}})
	guard, _ := NewGuard(policy, nil, nil)
	if _, err := NewSOCKS5(nil, &MemorySink{}); err == nil {
		t.Error("NewSOCKS5 accepted a nil guard")
	}
	if _, err := NewSOCKS5(guard, nil); err == nil {
		t.Error("NewSOCKS5 accepted a nil sink")
	}
	if s, err := NewSOCKS5(guard, &MemorySink{}); err != nil || s.handshakeTimeout != socksHandshakeTimeout || s.tunnelIdle != tunnelIdleTimeout {
		t.Errorf("NewSOCKS5 = %+v, %v; want the default timeouts", s, err)
	}
}

// temporaryError is an accept error that goes away by itself, like EMFILE.
type temporaryError struct{}

func (temporaryError) Error() string   { return "accept: too many open files" }
func (temporaryError) Temporary() bool { return true }
func (temporaryError) Timeout() bool   { return false }

// flakyListener fails Accept with a temporary error the first failures times,
// or always when failures is negative, before handing out real connections.
type flakyListener struct {
	net.Listener
	mu       sync.Mutex
	failures int
	failed   int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	fail := l.failures < 0 || l.failed < l.failures
	if fail {
		l.failed++
	}
	l.mu.Unlock()
	if fail {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: temporaryError{}}
	}
	return l.Listener.Accept()
}

func TestSOCKS5KeepsServingAfterTemporaryAcceptErrors(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := serveSOCKS(t, echoServer(t), nil, nil, &flakyListener{Listener: inner, failures: 4})
	conn := f.dial(t)
	greet(t, conn)

	code := replyCode(t, conn, domainRequest(0x01, "app.test", 443))

	if code != 0x00 {
		t.Fatalf("reply code = %#02x; want success after the accept errors passed", code)
	}
	select {
	case <-f.done:
		t.Fatalf("Serve returned %v after a temporary accept error", *f.serveErr)
	default:
	}
}

func TestSOCKS5ServeReturnsNilWhenCancelledWhileWaitingOutAcceptErrors(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := serveSOCKS(t, echoServer(t), nil, nil, &flakyListener{Listener: inner, failures: -1})
	time.Sleep(3 * socksAcceptRetryMin) // let Serve reach its backoff

	f.cancel()

	if err := f.stopped(t); err != nil {
		t.Fatalf("Serve = %v; want nil after its context was cancelled", err)
	}
}

func TestSOCKS5RefusesConnectionsBeyondTheLimit(t *testing.T) {
	f := newSOCKSFixture(t, echoServer(t), nil, func(s *SOCKS5) { s.maxConns = 2 })
	first, second := f.dial(t), f.dial(t)
	greet(t, first)
	greet(t, second)

	extra := f.dial(t)

	expectClosed(t, extra)
	if code := replyCode(t, first, domainRequest(0x01, "app.test", 443)); code != 0x00 {
		t.Fatalf("reply code = %#02x; a connection within the limit must still be served", code)
	}
	payload := []byte("still here")
	if _, err := first.Write(payload); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(first, echoed); err != nil || !bytes.Equal(echoed, payload) {
		t.Fatalf("echo = %q, err = %v", echoed, err)
	}
	second.Close()
	if err := waitForSlot(f); err != nil {
		t.Fatal(err)
	}
}

// waitForSlot dials until a connection is served again, which shows a slot is
// given back when a connection ends. It polls because the server notices the
// close at a time of its own.
func waitForSlot(f socksFixture) error {
	deadline := time.Now().Add(socksTestDeadline)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", f.addr)
		if err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte{0x05, 0x01, 0x00})
		var choice [2]byte
		if err == nil {
			_, err = io.ReadFull(conn, choice[:])
		}
		conn.Close()
		if err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("no connection was served after one within the limit closed")
}
