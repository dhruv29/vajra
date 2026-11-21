package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	sendTimeout         = 15 * time.Second
	connectTimeout      = 10 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	// maxResponseBytes caps how much of the reply is read. The reply is not
	// used; reading a little of it lets the server finish cleanly.
	maxResponseBytes = 64 << 10
	userAgent        = "vajra-notify"

	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// Options configures Send.
type Options struct {
	// URL is the webhook. It must be https; http is accepted only together
	// with AllowPrivate. It often embeds a token, so no error repeats more of
	// it than the scheme and host.
	URL string
	// HTTP is for tests. When set it replaces the guarded client, so the
	// address checks and Resolver do not apply; redirects are still refused.
	HTTP *http.Client
	// Resolver is used by the guarded client. Nil means the system resolver.
	Resolver Resolver
	// AllowPrivate permits a webhook on a loopback, link-local or private
	// address, for an internal chat server. It also permits plain http.
	AllowPrivate bool
}

// Send POSTs the summary as JSON to opts.URL. Any reply other than a 2xx is
// an error; a redirect is never followed, because it would carry the summary
// to an address the operator did not configure and nothing checked.
func Send(ctx context.Context, summary Summary, opts Options) error {
	target, err := checkURL(opts.URL, opts.AllowPrivate)
	if err != nil {
		return err
	}
	body, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("notify: encode summary: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.URL, bytes.NewReader(body))
	if err != nil {
		// The cause is not wrapped: it would repeat the URL.
		return fmt.Errorf("notify: build request for %s", target)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := clientFor(opts).Do(req)
	if err != nil {
		return fmt.Errorf("notify: post to %s: %w", target, withoutURL(err))
	}
	defer resp.Body.Close()
	// A failure to drain the reply does not change whether it was delivered.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	return checkStatus(target, resp.StatusCode)
}

// checkURL validates the webhook URL and returns the only form of it that
// may appear in an error: scheme and host.
func checkURL(raw string, allowPrivate bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse quotes its input, so its error is not passed on.
		return "", errors.New("notify: webhook URL is malformed")
	}
	if u.Hostname() == "" {
		return "", errors.New("notify: webhook URL has no host")
	}
	target := u.Scheme + "://" + u.Host
	if u.User != nil {
		return "", fmt.Errorf("notify: webhook URL for %s must not carry a user name or password", target)
	}
	switch u.Scheme {
	case schemeHTTPS:
	case schemeHTTP:
		if !allowPrivate {
			return "", fmt.Errorf("notify: webhook %s must use https; plain http is accepted only for an internal webhook with private addresses allowed", target)
		}
	default:
		return "", fmt.Errorf("notify: webhook scheme %q is not supported; use https", u.Scheme)
	}
	return target, nil
}

func checkStatus(target string, status int) error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status >= 300 && status < 400:
		return fmt.Errorf("notify: %s answered with a redirect (status %d), which is not followed", target, status)
	default:
		return fmt.Errorf("notify: %s returned status %d", target, status)
	}
}

// withoutURL drops the wrapper the HTTP client puts around a failure, since
// that wrapper's message contains the full request URL.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func clientFor(opts Options) *http.Client {
	if opts.HTTP != nil {
		// A copy, so the caller's client is not changed.
		client := *opts.HTTP
		client.CheckRedirect = noRedirect
		return &client
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	g := &guard{
		resolver:     resolver,
		dial:         (&net.Dialer{Timeout: connectTimeout}).DialContext,
		allowPrivate: opts.AllowPrivate,
	}
	return guardedClient(g)
}

// guardedClient builds a client whose every connection goes through g. The
// transport is built here, not cloned from the process default, so nothing
// set elsewhere (a proxy, relaxed TLS checks) can weaken it. Proxy stays nil:
// a proxy would do the resolving and connecting itself, past the guard.
func guardedClient(g *guard) *http.Client {
	return &http.Client{
		Timeout:       sendTimeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           g.dialContext,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: sendTimeout,
			ForceAttemptHTTP2:     true,
			// One request per client: nothing would reuse an idle connection.
			DisableKeepAlives: true,
		},
	}
}
