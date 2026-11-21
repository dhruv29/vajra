// Package sarif imports results from any static-analysis tool that writes
// SARIF 2.1.0 (CodeQL, Semgrep, Snyk, Trivy, Bandit, gosec, AI reviewers...)
// and checks each claim against the real source tree.
//
// A SARIF file is untrusted input from a tool Vajra did not run. Parse bounds
// how much it reads and keeps, and refuses any file path that could lead out
// of the project. Checker then treats every result as a claim about code and
// throws out the ones the code does not bear out.
package sarif

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// DefaultMaxBytes is how much of a SARIF document Parse reads by default.
	DefaultMaxBytes int64 = 64 << 20
	// DefaultMaxResults is how many results Parse keeps by default.
	DefaultMaxResults = 20000

	supportedVersion = "2.1.0"
)

// Options bound what Parse accepts. The zero value uses the defaults.
type Options struct {
	// MaxBytes caps the bytes read; a larger document is an error, because a
	// half-read report would silently drop findings.
	MaxBytes int64
	// MaxResults caps the results kept. Extra results are counted in
	// Stats.OverCap.
	MaxResults int
	// Root is the project's absolute path on this machine. When set, a result
	// whose location is an absolute path under Root is made relative to it.
	// Absolute paths anywhere else are always skipped.
	Root string
}

func (o Options) withDefaults() Options {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxResults <= 0 {
		o.MaxResults = DefaultMaxResults
	}
	return o
}

// Stats counts the results Parse did not return, by reason.
type Stats struct {
	// Excluded results are suppressed, absent from the baseline, or of a kind
	// that is not a failure.
	Excluded int
	// Unsafe results point at a path outside the project or that is otherwise
	// unsafe to open.
	Unsafe int
	// Unusable results have no rule, no file or no line.
	Unusable int
	// OverCap results came after MaxResults were already kept.
	OverCap int
	// Duplicate results repeat the rule, file and line of one already kept.
	Duplicate int
}

// Total is the number of results not returned.
func (s Stats) Total() int {
	return s.Excluded + s.Unsafe + s.Unusable + s.OverCap + s.Duplicate
}

// Parse reads a SARIF 2.1.0 log and returns its results as static candidate
// findings, sorted by file, line and rule. skipped is the number of results
// not returned; ParseWithStats breaks it down.
func Parse(r io.Reader, opts Options) (findings []finding.Finding, skipped int, err error) {
	findings, stats, err := ParseWithStats(r, opts)
	return findings, stats.Total(), err
}

// ParseWithStats is Parse with the skipped results counted by reason.
func ParseWithStats(r io.Reader, opts Options) ([]finding.Finding, Stats, error) {
	opts = opts.withDefaults()
	p := &parser{
		dec:  json.NewDecoder(&limitReader{r: r, left: opts.MaxBytes}),
		opts: opts,
	}
	if err := p.document(); err != nil {
		if errors.Is(err, errTooLarge) {
			return nil, p.stats, fmt.Errorf("sarif: the document is larger than %d bytes", opts.MaxBytes)
		}
		return nil, p.stats, fmt.Errorf("sarif: %w", err)
	}
	return p.finish(), p.stats, nil
}

var errTooLarge = errors.New("input too large")

// limitReader fails once more than the allowed bytes have been read, so an
// oversized document is an error rather than a silently truncated one.
type limitReader struct {
	r    io.Reader
	left int64
}

func (l *limitReader) Read(b []byte) (int, error) {
	if l.left > 0 {
		if int64(len(b)) > l.left {
			b = b[:l.left]
		}
		n, err := l.r.Read(b)
		l.left -= int64(n)
		return n, err
	}
	// The limit is used up: the document is too large only if more follows.
	var probe [1]byte
	n, err := io.ReadAtLeast(l.r, probe[:], 1)
	if n > 0 {
		return 0, errTooLarge
	}
	return 0, err
}

// parser streams the document: runs and results are decoded one at a time,
// so a file with millions of results never holds them all in memory.
type parser struct {
	dec   *json.Decoder
	opts  Options
	stats Stats
	kept  int
	out   []finding.Finding
}

func (p *parser) document() error {
	if err := p.expect('{'); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("the document is empty")
		}
		return err
	}
	sawRuns := false
	for p.dec.More() {
		key, err := p.key()
		if err != nil {
			return err
		}
		switch key {
		case "runs":
			sawRuns = true
			err = p.runs()
		case "version":
			err = p.version()
		default:
			err = p.skip()
		}
		if err != nil {
			return err
		}
	}
	if err := p.expect('}'); err != nil {
		return err
	}
	if !sawRuns {
		return errors.New("the document has no runs; it is not a SARIF log")
	}
	return nil
}

func (p *parser) version() error {
	var v string
	if err := p.dec.Decode(&v); err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if !strings.HasPrefix(v, supportedVersion) {
		return fmt.Errorf("version %q is not supported; want %s", clip(v, maxTitleBytes), supportedVersion)
	}
	return nil
}

func (p *parser) runs() error {
	if err := p.expect('['); err != nil {
		return fmt.Errorf("runs: %w", err)
	}
	for p.dec.More() {
		if err := p.run(); err != nil {
			return err
		}
	}
	return p.expect(']')
}

// run reads one run. Its results are held until the run ends, because the
// tool name and base URIs they depend on may come after them.
func (p *parser) run() error {
	if err := p.expect('{'); err != nil {
		return fmt.Errorf("run: %w", err)
	}
	var st runState
	var pending []result
	for p.dec.More() {
		key, err := p.key()
		if err != nil {
			return err
		}
		switch key {
		case "tool":
			err = p.lenient(&st.tool)
		case "originalUriBaseIds":
			err = p.lenient(&st.bases)
		case "results":
			pending, err = p.results(pending)
		default:
			err = p.skip()
		}
		if err != nil {
			return err
		}
	}
	if err := p.expect('}'); err != nil {
		return err
	}
	p.convert(st.prepare(p.opts.Root), pending)
	return nil
}

func (p *parser) results(pending []result) ([]result, error) {
	tok, err := p.dec.Token()
	if err != nil {
		return pending, err
	}
	if tok == nil {
		return pending, nil // "results": null means the tool did not run
	}
	if tok != json.Delim('[') {
		return pending, errors.New("results is not a list")
	}
	for p.dec.More() {
		var r result
		if err := p.lenient(&r); err != nil {
			return pending, err
		}
		switch {
		case r.excluded():
			p.stats.Excluded++
		case p.kept >= p.opts.MaxResults:
			p.stats.OverCap++
		default:
			p.kept++
			pending = append(pending, r)
		}
	}
	return pending, p.expect(']')
}

func (p *parser) convert(st *runState, pending []result) {
	for _, r := range pending {
		f, skip := st.toFinding(r)
		switch skip {
		case skipNone:
			p.out = append(p.out, f)
		case skipUnsafe:
			p.stats.Unsafe++
		default:
			p.stats.Unusable++
		}
	}
}

// lenient decodes the next value into v. A field of the wrong type leaves
// that field empty instead of failing the document; broken JSON still fails.
func (p *parser) lenient(v any) error {
	if err := p.dec.Decode(v); err != nil && !isTypeError(err) {
		return err
	}
	return nil
}

func (p *parser) skip() error {
	var raw json.RawMessage
	return p.dec.Decode(&raw)
}

func (p *parser) key() (string, error) {
	tok, err := p.dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected an object key, got %v", tok)
	}
	return key, nil
}

func (p *parser) expect(delim json.Delim) error {
	tok, err := p.dec.Token()
	if err != nil {
		return err
	}
	if tok != delim {
		return fmt.Errorf("expected %q, got %v", delim, tok)
	}
	return nil
}
