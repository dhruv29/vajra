package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dhruv29/vajra/internal/sandbox"
)

const outputCap = 160 << 20

// Fetcher makes HTTP requests on behalf of a scanner. *Runner is the real
// one; tests use fakes.
type Fetcher interface {
	Do(ctx context.Context, requests []Request) ([]Response, error)
}

// Runner sends batches to "vajra probe" in a sandbox behind the gate.
type Runner struct {
	Sandbox sandbox.Runner
	// Image must contain the vajra binary as its entrypoint.
	Image       string
	Network     string
	ProxyURL    string
	Timeout     time.Duration
	InsecureTLS bool
}

// Validate reports the first missing setting.
func (r *Runner) Validate() error {
	switch {
	case r.Sandbox == nil:
		return errors.New("probe: a sandbox runner is required")
	case r.Image == "":
		return errors.New("probe: an image is required")
	case r.Network == "" || r.Network == sandbox.NetworkNone:
		return errors.New("probe: an internal network is required")
	case r.ProxyURL == "":
		return errors.New("probe: the egress proxy URL is required")
	case r.Timeout <= 0:
		return errors.New("probe: a timeout is required")
	}
	return nil
}

// Do executes requests and returns one response per request, in order.
func (r *Runner) Do(ctx context.Context, requests []Request) ([]Response, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	batch := Batch{Requests: requests, InsecureTLS: r.InsecureTLS}
	if err := batch.Validate(); err != nil {
		return nil, err
	}
	stdin, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("probe: encode batch: %w", err)
	}
	result, err := r.Sandbox.Run(ctx, sandbox.Spec{
		Image:     r.Image,
		Argv:      []string{"probe", "-proxy", r.ProxyURL},
		Network:   r.Network,
		Timeout:   r.Timeout,
		OutputCap: outputCap,
		Stdin:     stdin,
	})
	if err != nil {
		return nil, fmt.Errorf("probe: %w", err)
	}
	if result.TimedOut {
		return nil, fmt.Errorf("probe: timed out after %s", r.Timeout)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("probe: exit code %d: %s", result.ExitCode, tail(result.Stderr))
	}
	if result.Truncated {
		return nil, errors.New("probe: output exceeded the capture limit; send fewer requests per batch")
	}
	var results Results
	if err := json.Unmarshal(bytes.TrimSpace(result.Stdout), &results); err != nil {
		return nil, fmt.Errorf("probe: decode results: %w", err)
	}
	if len(results.Responses) != len(requests) {
		return nil, fmt.Errorf("probe: %d responses for %d requests", len(results.Responses), len(requests))
	}
	for i, resp := range results.Responses {
		if resp.ID != requests[i].ID {
			return nil, fmt.Errorf("probe: response %d is for request %q, not %q", i, resp.ID, requests[i].ID)
		}
	}
	return results.Responses, nil
}

func tail(b []byte) string {
	text := strings.TrimSpace(string(b))
	if len(text) > 600 {
		text = text[len(text)-600:]
	}
	return text
}

// FormatRequest renders a request as text for evidence. Header values named
// in secretHeaders (compared case-insensitively) are replaced, so credentials
// used for testing never reach a report or a model.
func FormatRequest(r Request, secretHeaders []string) string {
	secret := map[string]bool{}
	for _, name := range secretHeaders {
		secret[strings.ToLower(name)] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", r.Method, r.URL)
	names := make([]string, 0, len(r.Headers))
	for name := range r.Headers {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		value := r.Headers[name]
		if secret[strings.ToLower(name)] {
			value = "[redacted]"
		}
		fmt.Fprintf(&b, "%s: %s\n", name, value)
	}
	if r.Body != "" {
		fmt.Fprintf(&b, "\n%s", r.Body)
	}
	return b.String()
}

// FormatResponse renders a response as text for evidence.
func FormatResponse(r Response) string {
	if r.Error != "" {
		return "no response: " + r.Error
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d\n", r.Status)
	names := make([]string, 0, len(r.Headers))
	for name := range r.Headers {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		if strings.EqualFold(name, "Set-Cookie") {
			fmt.Fprintf(&b, "%s: [redacted]\n", name) // session tokens stay out of reports
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", name, strings.Join(r.Headers[name], ", "))
	}
	fmt.Fprintf(&b, "\n%s", r.Body)
	if r.BodyTruncated {
		b.WriteString("\n[body truncated]")
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
