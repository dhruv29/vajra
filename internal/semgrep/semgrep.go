// Package semgrep runs the Semgrep static analyser inside the sandbox and
// turns its results into findings.
//
// The source tree is mounted read-only and the container has no network, so
// analysing untrusted code cannot change it or send it anywhere.
package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
)

const (
	// Source is the value of Finding.Source for results from this scanner.
	Source = "semgrep"

	sourceMount     = "/src"
	rulesMount      = "/rules"
	sandboxHome     = "/tmp"
	memoryMB        = 2048
	outputCap       = 64 << 20
	perFileTimeout  = "30"
	stderrTailBytes = 600
	maxTextBytes    = 2000
)

var cwePattern = regexp.MustCompile(`(?i)cwe-\d+`)

// Scanner runs Semgrep over one source tree.
type Scanner struct {
	Runner sandbox.Runner
	Image  string
	// SourceRoot is the absolute host path of the code to analyse.
	SourceRoot string
	// Exactly one of RulesHostDir (a host directory, mounted read-only) and
	// RulesImagePath (a path inside the image) says where the rules are. Rules
	// are never fetched at run time: the container has no network.
	RulesHostDir   string
	RulesImagePath string
	// AssetURL is the running service this code belongs to; it may be empty.
	AssetURL string
	Timeout  time.Duration
}

// Validate reports the first missing or inconsistent setting.
func (s *Scanner) Validate() error {
	switch {
	case s.Runner == nil:
		return errors.New("semgrep: a sandbox runner is required")
	case s.Image == "":
		return errors.New("semgrep: an image is required")
	case !filepath.IsAbs(s.SourceRoot) || filepath.Clean(s.SourceRoot) != s.SourceRoot:
		return fmt.Errorf("semgrep: source root %q must be a clean absolute path", s.SourceRoot)
	case (s.RulesHostDir == "") == (s.RulesImagePath == ""):
		return errors.New("semgrep: set exactly one of the rules host directory and the rules image path")
	case s.RulesImagePath != "" && !filepath.IsAbs(s.RulesImagePath):
		return fmt.Errorf("semgrep: rules image path %q must be absolute", s.RulesImagePath)
	case s.Timeout <= 0:
		return errors.New("semgrep: a timeout is required")
	}
	return nil
}

// Scan analyses the whole source tree and returns raw candidates.
func (s *Scanner) Scan(ctx context.Context) ([]finding.Finding, error) {
	return s.run(ctx, ".")
}

// Reproduce re-analyses only the file behind f and reports whether the same
// rule still matches the same line.
func (s *Scanner) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	if f.Location == nil || !finding.SafeRelPath(f.Location.File) {
		return false, errors.New("semgrep: the finding has no usable file location")
	}
	// The "./" prefix keeps a file name that starts with "-" from being read
	// as a command-line flag.
	results, err := s.run(ctx, "./"+f.Location.File)
	if err != nil {
		return false, err
	}
	for _, r := range results {
		if r.RuleID == f.RuleID && r.Location != nil && r.Location.File == f.Location.File && r.Location.Line == f.Location.Line {
			return true, nil
		}
	}
	return false, nil
}

func (s *Scanner) run(ctx context.Context, target string) ([]finding.Finding, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	rules := s.RulesImagePath
	mounts := []sandbox.Mount{{Source: s.SourceRoot, Target: sourceMount}}
	if s.RulesHostDir != "" {
		rules = rulesMount
		mounts = append(mounts, sandbox.Mount{Source: s.RulesHostDir, Target: rulesMount})
	}
	result, err := s.Runner.Run(ctx, sandbox.Spec{
		Image:      s.Image,
		Entrypoint: "semgrep",
		Argv: []string{
			"scan", "--json", "--quiet", "--dataflow-traces",
			"--metrics=off", "--disable-version-check", // a task has no network
			"--no-git-ignore", // the tree is read-only and may not be a usable repository
			"--timeout", perFileTimeout,
			"--config", rules,
			target,
		},
		Network: sandbox.NetworkNone,
		Mounts:  mounts,
		Workdir: sourceMount,
		Env: map[string]string{
			"HOME":                         sandboxHome,
			"SEMGREP_SEND_METRICS":         "off",
			"SEMGREP_ENABLE_VERSION_CHECK": "0",
		},
		Timeout:   s.Timeout,
		MemoryMB:  memoryMB,
		OutputCap: outputCap,
	})
	if err != nil {
		return nil, fmt.Errorf("semgrep: %w", err)
	}
	if result.TimedOut {
		return nil, fmt.Errorf("semgrep: timed out after %s", s.Timeout)
	}
	if result.Truncated {
		return nil, errors.New("semgrep: output exceeded the capture limit; narrow the rules or the source tree")
	}
	// Exit status 1 means "findings were reported"; anything higher is a failure.
	if result.ExitCode > 1 || result.ExitCode < 0 {
		return nil, fmt.Errorf("semgrep: exit code %d: %s", result.ExitCode, tail(result.Stderr))
	}
	findings, err := Parse(bytes.NewReader(result.Stdout))
	if err != nil {
		return nil, err
	}
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		f.AssetURL = s.AssetURL
		f.Evidence.Code = readContext(s.SourceRoot, f.Location)
		out = append(out, f)
	}
	return out, nil
}

type position struct {
	Line int `json:"line"`
}

type location struct {
	Path  string   `json:"path"`
	Start position `json:"start"`
	End   position `json:"end"`
}

type result struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   position `json:"start"`
	End     position `json:"end"`
	Extra   struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE      textList `json:"cwe"`
			Category string   `json:"category"`
		} `json:"metadata"`
		Trace *struct {
			Source       json.RawMessage `json:"taint_source"`
			Intermediate []struct {
				Location location `json:"location"`
				Content  string   `json:"content"`
			} `json:"intermediate_vars"`
			Sink json.RawMessage `json:"taint_sink"`
		} `json:"dataflow_trace"`
	} `json:"extra"`
}

// textList accepts a JSON string or a list of strings.
type textList []string

func (l *textList) UnmarshalJSON(raw []byte) error {
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		*l = many
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		*l = []string{one}
	}
	return nil // an unexpected shape is ignored, not fatal
}

// Parse reads Semgrep's JSON output. Results without a rule, a safe relative
// path or a line are dropped: they cannot be located or verified.
func Parse(r io.Reader) ([]finding.Finding, error) {
	var out struct {
		Results []result `json:"results"`
	}
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, fmt.Errorf("semgrep: decode output: %w", err)
	}
	findings := make([]finding.Finding, 0, len(out.Results))
	for _, res := range out.Results {
		path := strings.TrimPrefix(res.Path, "./")
		if res.CheckID == "" || !finding.SafeRelPath(path) || res.Start.Line < 1 {
			continue
		}
		findings = append(findings, res.toFinding(path))
	}
	return findings, nil
}

func (res result) toFinding(path string) finding.Finding {
	target := path + ":" + strconv.Itoa(res.Start.Line)
	end := res.End.Line
	if end < res.Start.Line {
		end = res.Start.Line
	}
	tags := []string{}
	if category := strings.ToLower(strings.TrimSpace(res.Extra.Metadata.Category)); category != "" {
		tags = append(tags, category)
	}
	return finding.Finding{
		ID:          finding.StableID(Source, res.CheckID, target, ""),
		Kind:        finding.Static,
		Source:      Source,
		RuleID:      res.CheckID,
		Title:       title(res.CheckID),
		Description: clip(res.Extra.Message),
		Severity:    severity(res.Extra.Severity),
		Target:      target,
		Location:    &finding.Location{File: path, Line: res.Start.Line, EndLine: end},
		Tags:        tags,
		CWE:         cwes(res.Extra.Metadata.CWE),
		Status:      finding.Candidate,
		Evidence:    finding.Evidence{Trace: res.trace()},
	}
}

// title turns "python.flask.security.injection.tainted-sql-string" into
// "tainted sql string".
func title(checkID string) string {
	name := checkID[strings.LastIndex(checkID, ".")+1:]
	return strings.ReplaceAll(name, "-", " ")
}

func severity(raw string) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "ERROR", "HIGH":
		return finding.SeverityHigh
	case "WARNING", "MEDIUM":
		return finding.SeverityMedium
	case "INFO", "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityUnknown
	}
}

// cwes extracts identifiers such as "cwe-89" from entries such as
// "CWE-89: Improper Neutralization of Special Elements ...".
func cwes(raw []string) []string {
	out := []string{}
	for _, entry := range raw {
		if id := cwePattern.FindString(entry); id != "" {
			out = append(out, strings.ToLower(id))
		}
	}
	return out
}

func (res result) trace() []finding.TraceStep {
	if res.Extra.Trace == nil {
		return nil
	}
	var steps []finding.TraceStep
	if step, ok := traceEnd("source", res.Extra.Trace.Source); ok {
		steps = append(steps, step)
	}
	for _, v := range res.Extra.Trace.Intermediate {
		steps = append(steps, finding.TraceStep{
			Role: "propagation", File: strings.TrimPrefix(v.Location.Path, "./"), Line: v.Location.Start.Line, Content: clip(v.Content),
		})
	}
	if step, ok := traceEnd("sink", res.Extra.Trace.Sink); ok {
		steps = append(steps, step)
	}
	return steps
}

// traceEnd reads Semgrep's tagged form ["CliLoc", [location, "content"]].
// Other variants are skipped.
func traceEnd(role string, raw json.RawMessage) (finding.TraceStep, bool) {
	var tagged []json.RawMessage
	if json.Unmarshal(raw, &tagged) != nil || len(tagged) != 2 {
		return finding.TraceStep{}, false
	}
	var pair []json.RawMessage
	if json.Unmarshal(tagged[1], &pair) != nil || len(pair) != 2 {
		return finding.TraceStep{}, false
	}
	var loc location
	var content string
	if json.Unmarshal(pair[0], &loc) != nil || json.Unmarshal(pair[1], &content) != nil || loc.Start.Line < 1 {
		return finding.TraceStep{}, false
	}
	return finding.TraceStep{Role: role, File: strings.TrimPrefix(loc.Path, "./"), Line: loc.Start.Line, Content: clip(content)}, true
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxTextBytes {
		return s[:maxTextBytes] + " [truncated]"
	}
	return s
}

func tail(b []byte) string {
	text := strings.TrimSpace(string(b))
	if len(text) > stderrTailBytes {
		text = text[len(text)-stderrTailBytes:]
	}
	return text
}
