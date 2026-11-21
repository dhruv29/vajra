package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://api.osv.dev"
	batchPath      = "/v1/querybatch"
	vulnPath       = "/v1/vulns/"

	// maxBatchQueries is the most queries the API takes in one request.
	maxBatchQueries  = 500
	maxResponseBytes = 8 << 20
	requestTimeout   = 30 * time.Second
	// maxPageRounds bounds how often continuation tokens are followed, so a
	// server that always returns one cannot keep a query running for ever.
	maxPageRounds = 50
	detailWorkers = 8
)

// Client queries the OSV API.
type Client struct {
	baseURL string
	http    *http.Client
}

// Options configures a Client. Both fields are optional.
type Options struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient builds a client for the public OSV API, or for opts.BaseURL when
// it is set.
func NewClient(opts Options) *Client {
	c := &Client{baseURL: strings.TrimRight(opts.BaseURL, "/"), http: opts.HTTP}
	if c.baseURL == "" {
		c.baseURL = defaultBaseURL
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	return c
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package   queryPackage `json:"package"`
	Version   string       `json:"version"`
	PageToken string       `json:"page_token,omitempty"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// pendingQuery is one package still to be asked about: for the first time,
// or again with the token for the next page of its results.
type pendingQuery struct {
	index int
	token string
}

// Query returns, for each package (same order and length as pkgs), the
// advisories that affect it. Any failed request fails the whole query: a
// lookup that did not happen must never read as "no known vulnerabilities".
func (c *Client) Query(ctx context.Context, pkgs []Package) ([][]Advisory, error) {
	ids, err := c.matchIDs(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	details, err := c.fetchDetails(ctx, distinct(ids))
	if err != nil {
		return nil, err
	}
	out := make([][]Advisory, len(pkgs))
	for i, pkg := range pkgs {
		for _, id := range ids[i] {
			out[i] = append(out[i], details[id].advisoryFor(id, pkg))
		}
	}
	return out, nil
}

// matchIDs asks which advisories affect each package and follows result
// pages until every package is answered in full.
func (c *Client) matchIDs(ctx context.Context, pkgs []Package) ([][]string, error) {
	ids := make([][]string, len(pkgs))
	todo := queryable(pkgs)
	for round := 0; len(todo) > 0; round++ {
		if round >= maxPageRounds {
			return nil, fmt.Errorf("osv: results still incomplete after %d pages", maxPageRounds)
		}
		var next []pendingQuery
		for chunk := range slices.Chunk(todo, maxBatchQueries) {
			results, err := c.queryBatch(ctx, pkgs, chunk)
			if err != nil {
				return nil, err
			}
			for i, result := range results {
				at := chunk[i].index
				for _, vuln := range result.Vulns {
					if vuln.ID != "" {
						ids[at] = append(ids[at], vuln.ID)
					}
				}
				if result.NextPageToken != "" {
					next = append(next, pendingQuery{index: at, token: result.NextPageToken})
				}
			}
		}
		todo = next
	}
	for i := range ids {
		slices.Sort(ids[i])
		ids[i] = slices.Compact(ids[i])
	}
	return ids, nil
}

// queryable lists the packages that can be asked about. One with no version
// is left out, because the API would answer with every advisory the package
// ever had.
func queryable(pkgs []Package) []pendingQuery {
	todo := make([]pendingQuery, 0, len(pkgs))
	for i, pkg := range pkgs {
		if pkg.Ecosystem != "" && pkg.Name != "" && pkg.Version != "" {
			todo = append(todo, pendingQuery{index: i})
		}
	}
	return todo
}

func (c *Client) queryBatch(ctx context.Context, pkgs []Package, chunk []pendingQuery) ([]batchResult, error) {
	queries := make([]batchQuery, len(chunk))
	for i, pending := range chunk {
		pkg := pkgs[pending.index]
		queries[i] = batchQuery{
			Package: queryPackage{Name: pkg.Name, Ecosystem: pkg.Ecosystem},
			Version: pkg.Version, PageToken: pending.token,
		}
	}
	body, err := json.Marshal(batchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("osv: encode batch query: %w", err)
	}
	var resp batchResponse
	if err := c.call(ctx, http.MethodPost, batchPath, body, "batch query", &resp); err != nil {
		return nil, err
	}
	// Results are matched to queries by position, so a reply of another
	// length cannot be attributed to packages at all.
	if len(resp.Results) != len(chunk) {
		return nil, fmt.Errorf("osv: batch query: %d results for %d queries", len(resp.Results), len(chunk))
	}
	return resp.Results, nil
}

func distinct(ids [][]string) []string {
	var all []string
	for _, list := range ids {
		all = append(all, list...)
	}
	slices.Sort(all)
	return slices.Compact(all)
}

// fetchDetails reads each advisory once, a few at a time, however many
// packages it affects. The first failure stops the rest.
func (c *Client) fetchDetails(ctx context.Context, ids []string) (map[string]vulnDetail, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
	)
	details := make(map[string]vulnDetail, len(ids))
	jobs := make(chan string)
	for range min(detailWorkers, len(ids)) {
		wg.Go(func() {
			for id := range jobs {
				detail, err := c.fetchDetail(ctx, id)
				mu.Lock()
				if err == nil {
					details[id] = detail
				} else if firstErr == nil {
					firstErr = err
					cancel()
				}
				mu.Unlock()
			}
		})
	}
	feed(ctx, jobs, ids)
	wg.Wait()
	if firstErr == nil && ctx.Err() != nil {
		firstErr = fmt.Errorf("osv: advisory lookup: %w", ctx.Err())
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return details, nil
}

func feed(ctx context.Context, jobs chan<- string, ids []string) {
	defer close(jobs)
	for _, id := range ids {
		select {
		case jobs <- id:
		case <-ctx.Done():
			return
		}
	}
}

func (c *Client) fetchDetail(ctx context.Context, id string) (vulnDetail, error) {
	var detail vulnDetail
	if err := c.call(ctx, http.MethodGet, vulnPath+url.PathEscape(id), nil, "advisory "+id, &detail); err != nil {
		return vulnDetail{}, err
	}
	if detail.ID == "" {
		return vulnDetail{}, fmt.Errorf("osv: advisory %s: the reply is not an advisory", id)
	}
	return detail, nil
}

// call makes one request and decodes the JSON reply into out. Errors name the
// HTTP status but never quote the body, which is untrusted and may be large.
func (c *Client) call(ctx context.Context, method, path string, body []byte, what string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("osv: %s: build request: %w", what, err)
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %s: %w", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv: %s: the API returned %d", what, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("osv: %s: read reply: %w", what, err)
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("osv: %s: %w", what, errReplyTooLarge)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("osv: %s: decode reply: %w", what, err)
	}
	return nil
}

var errReplyTooLarge = errors.New("the reply is larger than the read limit")
