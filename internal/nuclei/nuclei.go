// Package nuclei runs the nuclei scanner inside the sandbox and turns its
// output into findings.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/verify"
)

const (
	// Source is the value of Finding.Source for results from this scanner.
	Source = "nuclei"

	maxLineBytes     = 8 << 20
	stderrTailBytes  = 600
	defaultRateLimit = 20
	sandboxHome      = "/tmp"
)

var templateIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// record is the subset of a nuclei JSONL result that Vajra uses.
type record struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string     `json:"name"`
		Severity       string     `json:"severity"`
		Tags           stringList `json:"tags"`
		Classification struct {
			CWE stringList `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched-at"`
	MatcherName string   `json:"matcher-name"`
	Extracted   []string `json:"extracted-results"`
	Request     string   `json:"request"`
	Response    string   `json:"response"`
}

// stringList accepts a JSON array of strings or one comma-separated string,
// because scanner versions differ in how they write lists.
type stringList []string

func (l *stringList) UnmarshalJSON(raw []byte) error {
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		var one string
		if json.Unmarshal(raw, &one) != nil {
			return nil // an unexpected shape is ignored, not fatal
		}
		many = strings.Split(one, ",")
	}
	out := make([]string, 0, len(many))
	for _, item := range many {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			out = append(out, item)
		}
	}
	*l = out
	return nil
}

// Parse reads nuclei JSONL output. Lines that are not valid results, or that
// are longer than the line limit, are counted in skipped rather than failing
// the whole scan: one huge response must not cost every other finding.
func Parse(r io.Reader) (findings []finding.Finding, skipped int, err error) {
	reader := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, readErr := readLine(reader)
		if tooLong {
			skipped++
		} else if line = bytes.TrimSpace(line); len(line) > 0 {
			var rec record
			if json.Unmarshal(line, &rec) != nil || rec.TemplateID == "" {
				skipped++
			} else {
				findings = append(findings, rec.toFinding())
			}
		}
		if readErr == io.EOF {
			return findings, skipped, nil
		}
		if readErr != nil {
			return findings, skipped, fmt.Errorf("nuclei: read output: %w", readErr)
		}
	}
}

// readLine returns the next line. A line longer than maxLineBytes is consumed
// and reported as tooLong, with no content.
func readLine(reader *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, isPrefix, readErr := reader.ReadLine()
		if !tooLong {
			if len(line)+len(chunk) > maxLineBytes {
				line, tooLong = nil, true
			} else {
				line = append(line, chunk...)
			}
		}
		if readErr != nil || !isPrefix {
			return line, tooLong, readErr
		}
	}
}

func (rec record) toFinding() finding.Finding {
	target := rec.MatchedAt
	if target == "" {
		target = rec.Host
	}
	title := rec.Info.Name
	if title == "" {
		title = rec.TemplateID
	}
	return finding.Finding{
		ID:       finding.StableID(Source, rec.TemplateID, target, rec.MatcherName),
		Kind:     finding.Dynamic,
		Source:   Source,
		RuleID:   rec.TemplateID,
		Title:    title,
		Severity: finding.ParseSeverity(rec.Info.Severity),
		Target:   target,
		Tags:     rec.Info.Tags,
		CWE:      rec.Info.Classification.CWE,
		Status:   finding.Candidate,
		Evidence: finding.Evidence{
			Request:   rec.Request,
			Response:  rec.Response,
			MatchedAt: rec.MatchedAt,
			ScanInput: origin(target),
			Matcher:   rec.MatcherName,
			Extracted: rec.Extracted,
		},
	}
}

// origin returns scheme://host[:port] of a URL, or "" when it is not an http
// URL. It is the default starting point for reproducing a result.
func origin(target string) string {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Scanner runs nuclei in a sandbox whose only route out is the egress proxy.
type Scanner struct {
	Runner sandbox.Runner
	// Image must contain nuclei as its entrypoint and the templates at
	// TemplatesDir: a task container cannot download them.
	Image        string
	TemplatesDir string
	// Network is the internal Docker network the egress proxy is attached to.
	Network string
	// ProxyURL is the egress proxy as seen from that network.
	ProxyURL  string
	Timeout   time.Duration
	RateLimit int
	// CanaryTemplate is a template inside the image that matches any HTTP
	// response. It is run when a finding does not reproduce.
	CanaryTemplate string
	// Headers are sent with every request, for scanning as a test account.
	Headers map[string]string
}

// Validate reports the first missing setting.
func (s *Scanner) Validate() error {
	switch {
	case s.Runner == nil:
		return errors.New("nuclei: a sandbox runner is required")
	case s.Image == "" || s.TemplatesDir == "" || s.CanaryTemplate == "":
		return errors.New("nuclei: image, templates directory and canary template are required")
	case s.Network == "" || s.Network == sandbox.NetworkNone:
		return errors.New("nuclei: an internal network is required")
	case s.ProxyURL == "":
		return errors.New("nuclei: the egress proxy URL is required")
	case s.Timeout <= 0:
		return errors.New("nuclei: a timeout is required")
	}
	return nil
}

// Scan runs every template against the targets and returns raw candidates.
func (s *Scanner) Scan(ctx context.Context, targets []string) ([]finding.Finding, error) {
	if len(targets) == 0 {
		return nil, errors.New("nuclei: no targets")
	}
	args := s.baseArgs(s.TemplatesDir)
	for _, target := range targets {
		if _, _, err := verify.TargetHostPort(target); err != nil {
			return nil, fmt.Errorf("nuclei: target %q: %w", target, err)
		}
		args = append(args, "-target", target)
	}
	findings, err := s.run(ctx, args)
	if err != nil {
		return nil, err
	}
	return withScanInputs(findings, targets), nil
}

// withScanInputs records, on each finding, the configured target it came
// from. The scanner's own record of its input is not reliable, and a target
// with a path must be re-scanned with that path.
func withScanInputs(findings []finding.Finding, targets []string) []finding.Finding {
	byOrigin := make(map[string]string, len(targets))
	for _, target := range targets {
		if _, seen := byOrigin[origin(target)]; !seen {
			byOrigin[origin(target)] = target
		}
	}
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if input, ok := byOrigin[origin(f.Target)]; ok {
			f.Evidence.ScanInput = input
		}
		out = append(out, f)
	}
	return out
}

// Reproduce re-runs the one template behind f from the input the scanner was
// originally given, and reports whether the same rule matches the same place
// again. A template builds its own request path, so re-running it against the
// matched URL would test a different address.
//
// "No match" is reported only when the target demonstrably answered. If it
// did not, the result is an error, because a gate that is down or a target
// that has stopped responding says nothing about the finding.
func (s *Scanner) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	if !templateIDPattern.MatchString(f.RuleID) {
		return false, fmt.Errorf("nuclei: template id %q is malformed", f.RuleID)
	}
	input := f.Evidence.ScanInput
	if input == "" {
		input = f.Target
	}
	for _, u := range []string{input, f.Target} {
		if _, _, err := verify.TargetHostPort(u); err != nil {
			return false, fmt.Errorf("nuclei: target %q: %w", u, err)
		}
	}
	args := append(s.baseArgs(s.TemplatesDir), "-target", input, "-template-id", f.RuleID)
	results, err := s.run(ctx, args)
	if err != nil {
		return false, err
	}
	for _, r := range results {
		sameMatcher := f.Evidence.Matcher == "" || r.Evidence.Matcher == f.Evidence.Matcher
		if r.RuleID == f.RuleID && r.Target == f.Target && sameMatcher {
			return true, nil
		}
	}
	answered, err := s.targetAnswers(ctx, input)
	if err != nil {
		return false, err
	}
	if !answered {
		return false, fmt.Errorf("nuclei: %s did not answer, so the finding could not be re-tested", origin(input))
	}
	return false, nil
}

// targetAnswers runs the canary template, which matches any HTTP response.
func (s *Scanner) targetAnswers(ctx context.Context, input string) (bool, error) {
	results, err := s.run(ctx, append(s.baseArgs(s.CanaryTemplate), "-target", input))
	if err != nil {
		return false, err
	}
	for _, r := range results {
		if origin(r.Target) == origin(input) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Scanner) baseArgs(templates string) []string {
	rate := s.RateLimit
	if rate <= 0 {
		rate = defaultRateLimit
	}
	args := []string{
		"-jsonl", "-silent", "-no-color",
		"-disable-update-check", // a task has no route to the update server
		"-no-interactsh",        // out-of-band callbacks would leave the scope
		"-templates", templates,
		"-proxy", s.ProxyURL,
		"-rate-limit", strconv.Itoa(rate),
	}
	names := make([]string, 0, len(s.Headers))
	for name := range s.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args = append(args, "-header", name+": "+s.Headers[name])
	}
	return args
}

func (s *Scanner) run(ctx context.Context, args []string) ([]finding.Finding, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	env := sandbox.ProxyEnv(s.ProxyURL)
	env["HOME"] = sandboxHome // the root filesystem is read-only
	result, err := s.Runner.Run(ctx, sandbox.Spec{
		Image:   s.Image,
		Argv:    args,
		Network: s.Network,
		Env:     env,
		Timeout: s.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}
	if result.TimedOut {
		return nil, fmt.Errorf("nuclei: timed out after %s", s.Timeout)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("nuclei: exit code %d: %s", result.ExitCode, tail(result.Stderr))
	}
	if result.Truncated {
		return nil, errors.New("nuclei: output exceeded the capture limit; narrow the scan")
	}
	findings, _, err := Parse(bytes.NewReader(result.Stdout))
	return findings, err
}

func tail(b []byte) string {
	text := strings.TrimSpace(string(b))
	if len(text) > stderrTailBytes {
		text = text[len(text)-stderrTailBytes:]
	}
	return text
}
