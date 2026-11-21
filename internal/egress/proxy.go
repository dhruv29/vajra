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
	defaultHTTPPort       = "80"
)

// hopHeaders are meaningful for one connection only and are not forwarded.
var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Proxy is a forward proxy that serves plain-HTTP requests and CONNECT
// tunnels, and refuses anything the scope policy does not allow.
type Proxy struct {
	guard     *Guard
	sink      Sink
	transport *http.Transport
	now       func() time.Time
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
		},
		now: time.Now,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveHTTP(w, r)
}

func (p *Proxy) record(method, target string, err error) {
	e := Event{Time: p.now().UTC(), Method: method, Target: target, Allowed: err == nil}
	if err != nil {
		e.Reason = err.Error()
	}
	p.sink.Record(e)
}

// fail records the decision and answers the client: 403 for a scope denial,
// 502 for a target that is allowed but unreachable.
func (p *Proxy) fail(w http.ResponseWriter, method, target string, err error) {
	p.record(method, target, err)
	if scope.IsDenied(err) {
		http.Error(w, "blocked by scope policy: "+err.Error(), http.StatusForbidden)
		return
	}
	http.Error(w, "upstream unreachable", http.StatusBadGateway)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	defer cancel()
	upstream, err := p.guard.DialContext(ctx, "tcp", target)
	if err != nil {
		p.fail(w, r.Method, target, err)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.fail(w, r.Method, target, errors.New("connection cannot be tunnelled"))
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		p.record(r.Method, target, err)
		return
	}
	defer client.Close()
	p.record(r.Method, target, nil)

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	tunnel(client, buffered.Reader, upstream)
}

// tunnel copies bytes both ways until either side closes.
func tunnel(client net.Conn, clientReader io.Reader, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientReader)
		_ = upstream.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}()
	wg.Wait()
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
		p.fail(w, r.Method, target, err)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		p.fail(w, r.Method, target, err)
		return
	}
	defer resp.Body.Close()
	p.record(r.Method, target, nil)

	removeHopHeaders(resp.Header)
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
