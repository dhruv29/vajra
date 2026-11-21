// Package probe is Vajra's own HTTP client for reaching targets.
//
// It never runs on the host. The orchestrator starts "vajra probe" in a
// sandbox container on the task network, hands it a batch of requests on
// standard input, and reads the responses from standard output. Every request
// therefore passes through the egress gate like any other tool's traffic.
package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// MaxRequests is the most requests one batch may carry.
	MaxRequests = 500
	// MaxBodyBytes bounds each response body that is kept.
	MaxBodyBytes = 256 << 10
	// MaxRequestBodyBytes bounds each request body.
	MaxRequestBodyBytes = 1 << 20

	requestTimeout = 20 * time.Second
	gateHeader     = "X-Vajra-Gate"
)

// Request is one HTTP request to make.
type Request struct {
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Response is what came back for one request.
type Response struct {
	ID            string              `json:"id"`
	Status        int                 `json:"status"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Body          string              `json:"body,omitempty"`
	BodyTruncated bool                `json:"body_truncated,omitempty"`
	DurationMS    int64               `json:"duration_ms"`
	// Gate is set when the egress gate answered instead of the target:
	// "denied" (out of scope) or "failed" (target unreachable).
	Gate string `json:"gate,omitempty"`
	// Error is set when no HTTP response was received at all.
	Error string `json:"error,omitempty"`
}

// Answered reports whether the target itself produced this response.
func (r Response) Answered() bool {
	return r.Error == "" && r.Gate == "" && r.Status > 0
}

// Exchange is a request with its response.
type Exchange struct {
	Request  Request  `json:"request"`
	Response Response `json:"response"`
}

// Batch is the input of "vajra probe".
type Batch struct {
	Requests []Request `json:"requests"`
	// InsecureTLS accepts any certificate. Test targets often use self-signed
	// ones; the gate has already decided where the connection may go.
	InsecureTLS bool `json:"insecure_tls,omitempty"`
}

// Results is the output of "vajra probe".
type Results struct {
	Responses []Response `json:"responses"`
}

var allowedMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodOptions: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// Validate reports the first problem with a batch.
func (b Batch) Validate() error {
	if len(b.Requests) == 0 {
		return errors.New("probe: no requests")
	}
	if len(b.Requests) > MaxRequests {
		return fmt.Errorf("probe: %d requests exceed the limit of %d", len(b.Requests), MaxRequests)
	}
	for _, r := range b.Requests {
		if !allowedMethods[r.Method] {
			return fmt.Errorf("probe: request %q: method %q is not allowed", r.ID, r.Method)
		}
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return fmt.Errorf("probe: request %q: %q is not an http(s) URL", r.ID, r.URL)
		}
		// Credentials in a URL would be sent as a header nobody asked for, and
		// would be written into evidence with the URL.
		if u.User != nil {
			return fmt.Errorf("probe: request %q: a URL may not carry a user name or password", r.ID)
		}
		if len(r.Body) > MaxRequestBodyBytes {
			return fmt.Errorf("probe: request %q: body is too large", r.ID)
		}
	}
	return nil
}

// NewClient returns the HTTP client the probe uses inside the sandbox. It
// sends everything through proxyURL (the egress gate) and never follows a
// redirect: the caller sees the redirect and decides, so a target cannot steer
// the probe somewhere else unseen.
func NewClient(proxyURL string, insecureTLS bool) (*http.Client, error) {
	gate, err := url.Parse(proxyURL)
	if err != nil || gate.Scheme != "http" || gate.Host == "" {
		return nil, fmt.Errorf("probe: proxy %q must look like http://host:port", proxyURL)
	}
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(gate),
			DisableCompression: true,
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: insecureTLS}, //nolint:gosec // opt-in per batch, see Batch.InsecureTLS
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// Execute makes every request in order and returns one response per request.
// A request that fails does not stop the batch.
func Execute(ctx context.Context, client *http.Client, batch Batch) Results {
	out := Results{Responses: make([]Response, 0, len(batch.Requests))}
	for _, r := range batch.Requests {
		if ctx.Err() != nil {
			out.Responses = append(out.Responses, Response{ID: r.ID, Error: "cancelled before this request was sent"})
			continue
		}
		out.Responses = append(out.Responses, do(ctx, client, r))
	}
	return out
}

func do(ctx context.Context, client *http.Client, r Request) Response {
	started := time.Now()
	resp := Response{ID: r.ID}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, strings.NewReader(r.Body))
	if err != nil {
		resp.Error = "invalid request: " + err.Error()
		return resp
	}
	for name, value := range r.Headers {
		req.Header.Set(name, value)
	}
	httpResp, err := client.Do(req)
	resp.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		resp.Error = describe(err)
		return resp
	}
	defer httpResp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(httpResp.Body, MaxBodyBytes+1))
	if len(body) > MaxBodyBytes {
		body, resp.BodyTruncated = body[:MaxBodyBytes], true
	}
	resp.Status, resp.Body = httpResp.StatusCode, string(body)
	if readErr != nil {
		// A response cut off mid-body is not an answer: reporting it as a
		// complete 200 would let a failing target look like a served page.
		resp.Error = "the response ended before its body was complete: " + describe(readErr)
	}
	// Only a plain-HTTP response can have been written by the gate. HTTPS
	// goes through a tunnel the gate cannot write into, so there the header
	// can only come from the target, pretending.
	if strings.HasPrefix(r.URL, "http://") {
		resp.Gate = httpResp.Header.Get(gateHeader)
	}
	httpResp.Header.Del(gateHeader)
	resp.Headers = httpResp.Header
	resp.DurationMS = time.Since(started).Milliseconds()
	return resp
}

// describe gives a short reason for a failed request. A CONNECT tunnel the
// gate refused surfaces as a transport error, so it is named for what it is.
func describe(err error) string {
	text := err.Error()
	switch {
	case strings.Contains(text, "Forbidden"):
		return "the egress gate refused this connection (out of scope)"
	case strings.Contains(text, "Bad Gateway"):
		return "the egress gate could not reach the target"
	}
	if len(text) > 300 {
		text = text[:300]
	}
	return text
}

// Run is the body of the "vajra probe" command: read a batch, execute it
// through the gate, write the results.
func Run(ctx context.Context, proxyURL string, in io.Reader, out io.Writer) error {
	var batch Batch
	if err := json.NewDecoder(io.LimitReader(in, MaxRequests*(MaxRequestBodyBytes+4096))).Decode(&batch); err != nil {
		return fmt.Errorf("probe: read batch: %w", err)
	}
	if err := batch.Validate(); err != nil {
		return err
	}
	client, err := NewClient(proxyURL, batch.InsecureTLS)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(Execute(ctx, client, batch))
}
