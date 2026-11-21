package ticket

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
	"strings"
	"time"
	"unicode"
)

const (
	requestTimeout      = 20 * time.Second
	connectTimeout      = 10 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	// maxRequestBytes caps what is sent. Clipped titles and bodies stay well
	// under it; it guards against an encoding that grew unexpectedly.
	maxRequestBytes = 1 << 20
	// maxResponseBytes caps what is read. A search or create reply is a few
	// kilobytes; anything far larger is not a reply worth parsing.
	maxResponseBytes = 1 << 20
	// maxErrorMessageRunes is how much of a tracker's error message is kept.
	maxErrorMessageRunes = 200
	userAgent            = "vajra-ticket"

	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// apiClient sends JSON requests to one tracker's API.
type apiClient struct {
	// service names the tracker in errors ("github", "jira").
	service string
	// base is the API's base URL with no trailing slash. It was checked by
	// checkBaseURL and has no user information, so it may appear in errors.
	base string
	http *http.Client
	// authorize adds the credentials to a request.
	authorize func(*http.Request)
	// secrets are removed from any text a tracker sends back, in case a
	// misbehaving server echoes a credential into an error message.
	secrets []string
}

func newAPIClient(service, rawBase string, hc *http.Client, authorize func(*http.Request), secrets ...string) (*apiClient, error) {
	base, err := checkBaseURL(service, rawBase)
	if err != nil {
		return nil, err
	}
	return &apiClient{service: service, base: base, http: clientFor(hc), authorize: authorize, secrets: secrets}, nil
}

// checkBaseURL accepts https, and plain http only to a loopback address so
// that tests and local stand-ins work. Credentials must never cross the
// network in clear text. User information is refused: credentials belong in
// the option fields, where they are kept out of errors.
func checkBaseURL(service, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse quotes its input, which may hold a credential.
		return "", fmt.Errorf("ticket: %s API URL is malformed", service)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("ticket: %s API URL has no host", service)
	}
	origin := u.Scheme + "://" + u.Host
	if u.User != nil {
		return "", fmt.Errorf("ticket: %s API URL %s must not carry a user name or password", service, origin)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("ticket: %s API URL %s must not have a query or fragment", service, origin)
	}
	switch u.Scheme {
	case schemeHTTPS:
	case schemeHTTP:
		if !isLoopback(u.Hostname()) {
			return "", fmt.Errorf("ticket: %s API URL %s must use https; plain http is accepted only for a loopback address", service, origin)
		}
	default:
		return "", fmt.Errorf("ticket: %s API URL scheme %q is not supported; use https", service, u.Scheme)
	}
	return origin + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// isLoopback accepts only a literal loopback address. A name such as
// "localhost" is refused because resolving it is up to the system's
// configuration, which this check cannot see.
func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// do sends a request to escapedPath under the base URL. in, when not nil,
// is sent as JSON; a 2xx reply is decoded into out.
func (c *apiClient) do(ctx context.Context, method, escapedPath string, query url.Values, in, out any) error {
	body, err := encodeRequest(c.service, in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	target := c.base + escapedPath
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		// The cause is not wrapped: it would repeat the URL.
		return fmt.Errorf("ticket: build %s request to %s", c.service, c.base)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ticket: %s request to %s: %w", c.service, c.base, withoutURL(err))
	}
	defer resp.Body.Close()
	raw, err := readCapped(resp.Body)
	if err != nil {
		return fmt.Errorf("ticket: %s reply from %s: %w", c.service, c.base, err)
	}
	if err := c.checkStatus(resp.StatusCode, raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("ticket: %s reply from %s is not the JSON expected", c.service, c.base)
	}
	return nil
}

func encodeRequest(service string, in any) (io.Reader, error) {
	if in == nil {
		return nil, nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("ticket: encode %s request: %w", service, err)
	}
	if len(raw) > maxRequestBytes {
		return nil, fmt.Errorf("ticket: %s request is %d bytes, more than the %d allowed", service, len(raw), maxRequestBytes)
	}
	return bytes.NewReader(raw), nil
}

var errReplyTooLarge = fmt.Errorf("reply is larger than %d bytes", maxResponseBytes)

// readCapped reads a reply, refusing one over maxResponseBytes rather than
// parsing a truncated document.
func readCapped(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, withoutURL(err)
	}
	if len(raw) > maxResponseBytes {
		return nil, errReplyTooLarge
	}
	return raw, nil
}

func (c *apiClient) checkStatus(status int, raw []byte) error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status >= 300 && status < 400:
		return fmt.Errorf("ticket: %s at %s answered with a redirect (status %d), which is not followed", c.service, c.base, status)
	}
	msg := c.errorMessage(raw)
	if msg == "" {
		return fmt.Errorf("ticket: %s at %s returned status %d", c.service, c.base, status)
	}
	return fmt.Errorf("ticket: %s at %s returned status %d: %s", c.service, c.base, status, msg)
}

// errorMessage pulls the human-readable part out of an error reply, clipped
// and printable, with any credential removed.
func (c *apiClient) errorMessage(raw []byte) string {
	msg := messageFromJSON(raw)
	if msg == "" {
		msg = string(raw)
	}
	for _, secret := range c.secrets {
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "[redacted]")
		}
	}
	return clipRunes(strings.Join(strings.Fields(printable(msg)), " "), maxErrorMessageRunes)
}

// errorReply covers both trackers' error shapes: GitHub's "message" and
// Jira's "errorMessages" plus per-field "errors".
type errorReply struct {
	Message       string            `json:"message"`
	ErrorMessages []string          `json:"errorMessages"`
	Errors        map[string]string `json:"errors"`
}

func messageFromJSON(raw []byte) string {
	var reply errorReply
	if json.Unmarshal(raw, &reply) != nil {
		return ""
	}
	parts := []string{}
	if reply.Message != "" {
		parts = append(parts, reply.Message)
	}
	parts = append(parts, reply.ErrorMessages...)
	for field, text := range reply.Errors {
		parts = append(parts, field+": "+text)
	}
	return strings.Join(parts, "; ")
}

func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

// withoutURL drops the wrapper the HTTP client puts around a failure, since
// that wrapper's message contains the full request URL with its query.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// noRedirect refuses every redirect. Following one would send the
// credentials, and the finding, to an address nobody configured.
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// clientFor returns a copy of hc with redirects refused and a timeout set,
// or a fresh client when hc is nil. The transport is built here rather than
// taken from the process default, so nothing set elsewhere (relaxed TLS
// checks, for one) can weaken it. The proxy from the environment is kept:
// trackers are often reached through a corporate proxy, and TLS still runs
// end to end through it.
func clientFor(hc *http.Client) *http.Client {
	if hc != nil {
		client := *hc
		client.CheckRedirect = noRedirect
		if client.Timeout == 0 {
			client.Timeout = requestTimeout
		}
		return &client
	}
	return &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: connectTimeout}).DialContext,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: requestTimeout,
			ForceAttemptHTTP2:     true,
			DisableKeepAlives:     true,
		},
	}
}
