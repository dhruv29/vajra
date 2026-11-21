// Package apitest checks an API against its own description: every operation
// the OpenAPI document marks as needing authentication is requested without
// any, and one that answers anyway is reported.
package apitest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/openapi"
	"github.com/dhruv29/vajra/internal/probe"
)

const (
	// Source is the value of Finding.Source for results from this package.
	Source = "vajra-api"

	ruleAuthNotEnforced = "auth-not-enforced"
)

// Tester runs the checks for one API description.
type Tester struct {
	fetcher probe.Fetcher
	doc     openapi.Document
	opts    openapi.RequestOptions
	// byFinding remembers the request behind each finding, for re-testing.
	byFinding map[string]probe.Request
	// Skipped lists operations that could not be tested, and why.
	Skipped []openapi.Skipped
}

// New prepares a tester. Only read-only operations are requested: the checks
// send requests without credentials, and a request that changed data would be
// harmful exactly when the flaw exists.
func New(fetcher probe.Fetcher, doc openapi.Document, baseURL string, params map[string]string) (*Tester, error) {
	if fetcher == nil {
		return nil, errors.New("apitest: a fetcher is required")
	}
	// A base URL that is not http(s) would make every operation unbuildable,
	// and "nothing could be tested" must not read as "nothing was found".
	baseURL = strings.TrimSpace(baseURL)
	if u, err := url.Parse(baseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("apitest: base URL %q must be an http(s) URL", baseURL)
	}
	return &Tester{
		fetcher: fetcher, doc: doc, byFinding: map[string]probe.Request{},
		opts: openapi.RequestOptions{BaseURL: baseURL, Params: params},
	}, nil
}

// Run requests every protected read-only operation anonymously and returns a
// candidate finding for each one that was served.
func (t *Tester) Run(ctx context.Context) ([]finding.Finding, error) {
	requests, skipped := t.doc.Requests(t.opts)
	t.Skipped = skipped
	protected := map[string]openapi.Operation{}
	for _, op := range t.doc.Operations {
		if op.RequiresAuth {
			protected[op.ID] = op
		}
	}
	var batch []probe.Request
	for _, r := range requests {
		// OPTIONS is left out: servers answer preflight requests without
		// credentials by design, which says nothing about the operation.
		if _, ok := protected[r.ID]; ok && r.Method != http.MethodOptions {
			batch = append(batch, r)
		}
	}
	findings := []finding.Finding{}
	for start := 0; start < len(batch); start += probe.MaxRequests {
		chunk := batch[start:min(start+probe.MaxRequests, len(batch))]
		responses, err := t.fetcher.Do(ctx, chunk)
		if err != nil {
			return nil, fmt.Errorf("apitest: %w", err)
		}
		for i, resp := range responses {
			if served(resp) {
				f := t.finding(protected[chunk[i].ID], chunk[i], resp)
				t.byFinding[f.ID] = chunk[i]
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

func served(r probe.Response) bool {
	return r.Answered() && r.Status >= http.StatusOK && r.Status < http.StatusMultipleChoices
}

func (t *Tester) finding(op openapi.Operation, req probe.Request, resp probe.Response) finding.Finding {
	return finding.Finding{
		ID:     finding.StableID(Source, ruleAuthNotEnforced, op.Method+" "+op.Path, ""),
		Kind:   finding.Dynamic,
		Source: Source,
		RuleID: ruleAuthNotEnforced,
		Title:  fmt.Sprintf("%s %s answers without authentication", op.Method, op.Path),
		Description: fmt.Sprintf("The API description says %q requires authentication, but a request with no credentials was answered with HTTP %d.",
			op.ID, resp.Status),
		Severity: finding.SeverityHigh,
		Target:   req.URL,
		CWE:      []string{"cwe-306"},
		Tags:     []string{"api", "access-control"},
		Status:   finding.Candidate,
		Evidence: finding.Evidence{
			Request:   probe.FormatRequest(req, nil),
			Response:  probe.FormatResponse(resp),
			MatchedAt: req.URL,
			Matcher:   op.ID,
		},
	}
}

// Reproduce repeats the anonymous request behind f. A target that does not
// answer is an error, not a miss.
func (t *Tester) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	req, ok := t.byFinding[f.ID]
	if !ok {
		return false, errors.New("apitest: this finding did not come from the current API description")
	}
	responses, err := t.fetcher.Do(ctx, []probe.Request{req})
	if err != nil {
		return false, fmt.Errorf("apitest: %w", err)
	}
	if !responses[0].Answered() {
		return false, fmt.Errorf("apitest: %s did not answer, so the finding could not be re-tested", req.URL)
	}
	return served(responses[0]), nil
}
