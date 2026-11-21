package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dhruv29/vajra/internal/scope"
)

const (
	responseHeaderTimeout = 60 * time.Second
	dialTimeout           = 15 * time.Second
	upstreamIdleTimeout   = 90 * time.Second
	maxIdleUpstreams      = 64
	// tunnelIdleTimeout closes a tunnel that has carried nothing in either
	// direction for this long, so a silent peer cannot hold it open forever.
	tunnelIdleTimeout = 5 * time.Minute
	tunnelBufferBytes = 32 << 10
	defaultHTTPPort   = "80"

	// GateHeader marks a response the gate wrote itself, as opposed to one it
	// relayed from a target. Without it a client cannot tell "the target
	// answered 502" from "the gate could not reach the target".
	GateHeader = "X-Vajra-Gate"
)

// hopHeaders are meaningful for one connection only and are not forwarded.
var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Proxy is a forward proxy that serves plain-HTTP requests and CONNECT
// tunnels, and refuses anything the scope policy does not allow.
type Proxy struct {
	guard      *Guard
	sink       Sink
	transport  *http.Transport
	now        func() time.Time
	tunnelIdle time.Duration
}

// NewProxy builds a proxy around guard. Every decision is sent to sink.
func NewProxy(guard *Guard, sink Sink) (*Proxy, error) {
	if guard == nil {
		return nil, errors.New("egress: a guard is required")
	}
	if sink == nil {
		return nil, errors.New("egress: an audit sink is required")
	}
	return &Proxy{
		guard: guard,
		sink:  sink,
		transport: &http.Transport{
			Proxy:                 nil, // never chain through an environment proxy
			DialContext:           guard.DialContext,
			DisableCompression:    true,
			ResponseHeaderTimeout: responseHeaderTimeout,
			IdleConnTimeout:       upstreamIdleTimeout,
			MaxIdleConns:          maxIdleUpstreams,
		},
		now:        time.Now,
		tunnelIdle: tunnelIdleTimeout,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveHTTP(w, r)
}

// record writes one audit event and reports whether it was written.
func (p *Proxy) record(method, target string, outcome Outcome, reason string) bool {
	return p.sink.Record(Event{
		Time: p.now().UTC(), Method: method, Target: target,
		Allowed: outcome != Denied, Outcome: outcome, Reason: reason,
	}) == nil
}

// refuse records why a connection did not go through and answers the client:
// 403 when the policy denied it, 502 when the target could not be reached.
func (p *Proxy) refuse(w http.ResponseWriter, method, target string, err error) {
	if scope.IsDenied(err) {
		p.record(method, target, Denied, err.Error())
		w.Header().Set(GateHeader, string(Denied))
		http.Error(w, "blocked by scope policy: "+err.Error(), http.StatusForbidden)
		return
	}
	p.record(method, target, Failed, err.Error())
	w.Header().Set(GateHeader, string(Failed))
	http.Error(w, "upstream unreachable", http.StatusBadGateway)
}

func unaudited(w http.ResponseWriter) {
	w.Header().Set(GateHeader, "unaudited")
	http.Error(w, "the audit log could not be written, so nothing is forwarded", http.StatusServiceUnavailable)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	defer cancel()
	upstream, err := p.guard.DialContext(ctx, "tcp", target)
	if err != nil {
		p.refuse(w, r.Method, target, err)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.refuse(w, r.Method, target, errors.New("connection cannot be tunnelled"))
		return
	}
	// The decision is logged before the client is told the tunnel is open.
	if !p.record(r.Method, target, Allowed, "") {
		unaudited(w)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	tunnel(client, buffered.Reader, upstream, p.tunnelIdle)
}

// tunnel copies bytes both ways until either side closes or the tunnel has
// been idle, in both directions, for the idle timeout.
func tunnel(client net.Conn, clientReader io.Reader, upstream net.Conn, idle time.Duration) {
	touch := func() {
		deadline := time.Now().Add(idle)
		_ = client.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipe(upstream, clientReader, touch)
		_ = upstream.Close()
	}()
	go func() {
		defer wg.Done()
		pipe(client, upstream, touch)
		_ = client.Close()
	}()
	wg.Wait()
}

// pipe copies src to dst, calling touch around every read so that activity in
// either direction keeps the tunnel alive.
func pipe(dst io.Writer, src io.Reader, touch func()) {
	buf := make([]byte, tunnelBufferBytes)
	for {
		touch()
		n, err := src.Read(buf)
		if n > 0 {
			touch()
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		http.Error(w, "this is a forward proxy: send an absolute http:// URL or use CONNECT", http.StatusBadRequest)
		return
	}
	target := r.URL.Host
	if r.URL.Port() == "" {
		target = net.JoinHostPort(r.URL.Hostname(), defaultHTTPPort)
	}
	// Checked here as well as at dial time so that a request reusing an open
	// connection is still audited and still subject to the name check.
	if err := p.guard.CheckTarget(target); err != nil {
		p.refuse(w, r.Method, target, err)
		return
	}
	// Logged before the request is sent, so nothing reaches a target unaudited.
	if !p.record(r.Method, target, Allowed, "") {
		unaudited(w)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		// A denial here comes from the address check made while connecting.
		p.refuse(w, r.Method, target, err)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	resp.Header.Del(GateHeader) // a target may not impersonate the gate
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func removeHopHeaders(h http.Header) {
	for _, name := range hopHeaders {
		h.Del(name)
	}
}
