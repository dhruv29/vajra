package sarif

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	// SourcePrefix starts Finding.Source for every imported result; the rest
	// is the tool's name reduced to [a-z0-9-].
	SourcePrefix = "sarif:"

	unknownTool     = "unknown"
	maxToolNameLen  = 40
	maxRuleIDBytes  = 256
	maxTitleBytes   = 200
	maxMessageBytes = 2000
	maxSnippetBytes = 4000
	maxTagBytes     = 64
	maxTags         = 32
	maxCWEs         = 16
	maxCWENumber    = 99999
)

// skipReason says why a result did not become a finding.
type skipReason int

const (
	skipNone skipReason = iota
	skipUnsafe
	skipUnusable
)

var (
	sourcePattern = regexp.MustCompile(`^sarif:[a-z0-9]+(?:-[a-z0-9]+)*$`)
	// cwePattern finds "CWE-79", "external/cwe/cwe-079" or "cwe_79".
	cwePattern = regexp.MustCompile(`(?i)(?:^|[^a-z])cwe[-_/: ]?0*([0-9]{1,5})\b`)
)

// IsSource reports whether s is a Finding.Source this package produces.
func IsSource(s string) bool {
	return len(s) <= len(SourcePrefix)+maxToolNameLen && sourcePattern.MatchString(s)
}

// sourceFor turns a tool name such as "CodeQL" or "Snyk Open Source" into a
// Source such as "sarif:codeql" or "sarif:snyk-open-source".
func sourceFor(toolName string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(toolName) {
		if b.Len() >= maxToolNameLen {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		name = unknownTool
	}
	return SourcePrefix + name
}

// runState is what one run contributes to each of its results.
type runState struct {
	tool   toolInfo
	bases  baseIDs
	source string
	byID   map[string]*rule
	paths  resolver
}

func (st *runState) prepare(root string) *runState {
	st.source = sourceFor(st.tool.Driver.Name)
	st.byID = make(map[string]*rule, len(st.tool.Driver.Rules))
	for i := range st.tool.Driver.Rules {
		if id := st.tool.Driver.Rules[i].ID; id != "" {
			if _, seen := st.byID[id]; !seen {
				st.byID[id] = &st.tool.Driver.Rules[i]
			}
		}
	}
	st.paths = newResolver(st.bases, root)
	return st
}

// ruleFor finds the rule a result refers to, by index first (as the spec
// prefers) and by id otherwise. It returns the rule id and the rule, if any.
func (st *runState) ruleFor(r result) (string, *rule) {
	id := r.RuleID
	if id == "" {
		id = r.Rule.ID
	}
	index := r.RuleIndex
	if index == nil {
		index = r.Rule.Index
	}
	rules := st.tool.Driver.Rules
	if index != nil && *index >= 0 && *index < len(rules) && (id == "" || rules[*index].ID == id) {
		return rules[*index].ID, &rules[*index]
	}
	return id, st.byID[id]
}

func (st *runState) toFinding(r result) (finding.Finding, skipReason) {
	id, desc := st.ruleFor(r)
	id = clipLine(id, maxRuleIDBytes)
	if id == "" || len(r.Locations) == 0 {
		return finding.Finding{}, skipUnusable
	}
	phys := r.Locations[0].PhysicalLocation
	if phys.ArtifactLocation.URI == "" {
		return finding.Finding{}, skipUnusable
	}
	path, ok := st.paths.resolve(phys.ArtifactLocation)
	if !ok {
		return finding.Finding{}, skipUnsafe
	}
	if phys.Region.StartLine < 1 {
		return finding.Finding{}, skipUnusable
	}
	return st.build(r, id, desc, path, phys.Region), skipNone
}

func (st *runState) build(r result, id string, desc *rule, path string, reg region) finding.Finding {
	target := path + ":" + strconv.Itoa(reg.StartLine)
	f := finding.Finding{
		ID:          finding.StableID(st.source, id, target, ""),
		Kind:        finding.Static,
		Source:      st.source,
		RuleID:      id,
		Title:       title(id, desc),
		Description: description(r, desc),
		Severity:    severity(r, desc),
		Target:      target,
		Location:    &finding.Location{File: path, Line: reg.StartLine, EndLine: max(reg.StartLine, reg.EndLine)},
		Tags:        tags(r, desc),
		CWE:         cwes(r, desc),
		Status:      finding.Candidate,
	}
	// The tool's snippet is kept as what it extracted, so the checker can
	// compare it with the real file. Evidence.Code is only ever what Vajra
	// read itself.
	if snippet := clipRaw(reg.Snippet.Text, maxSnippetBytes); strings.TrimSpace(snippet) != "" {
		f.Evidence.Extracted = []string{snippet}
	}
	return f
}

func title(id string, desc *rule) string {
	if desc != nil {
		for _, t := range []string{desc.ShortDescription.Text, desc.Name} {
			if t = clipLine(t, maxTitleBytes); t != "" {
				return t
			}
		}
	}
	return id
}

func description(r result, desc *rule) string {
	if text := clip(r.Message.Text, maxMessageBytes); text != "" || desc == nil {
		return text
	}
	return clip(desc.FullDescription.Text, maxMessageBytes)
}

// severity prefers a numeric security-severity (on the result, then the
// rule) and falls back to the SARIF level.
func severity(r result, desc *rule) finding.Severity {
	if r.Properties.SecuritySeverity.ok {
		return fromScore(r.Properties.SecuritySeverity.value)
	}
	if desc != nil && desc.Properties.SecuritySeverity.ok {
		return fromScore(desc.Properties.SecuritySeverity.value)
	}
	level := r.Level
	if level == "" && desc != nil {
		level = desc.DefaultConfiguration.Level
	}
	return fromLevel(level)
}

// Score thresholds used by GitHub code scanning for security-severity.
const (
	criticalScore = 9.0
	highScore     = 7.0
	mediumScore   = 4.0
)

func fromScore(s float64) finding.Severity {
	switch {
	case s >= criticalScore:
		return finding.SeverityCritical
	case s >= highScore:
		return finding.SeverityHigh
	case s >= mediumScore:
		return finding.SeverityMedium
	case s > 0:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// fromLevel maps a SARIF level. An absent level means "warning" (SARIF
// §3.27.10).
func fromLevel(level string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return finding.SeverityHigh
	case "warning", "":
		return finding.SeverityMedium
	case "note":
		return finding.SeverityLow
	case "none":
		return finding.SeverityInfo
	default:
		return finding.SeverityUnknown
	}
}

func tags(r result, desc *rule) []string {
	raw := slices.Clone([]string(r.Properties.Tags))
	if desc != nil {
		raw = append(raw, desc.Properties.Tags...)
	}
	var out []string
	for _, t := range raw {
		if t = strings.ToLower(clipLine(t, maxTagBytes)); t != "" {
			out = append(out, t)
		}
	}
	return capSorted(out, maxTags)
}

// cwes collects CWE ids from tags (CodeQL's "external/cwe/cwe-079", Semgrep's
// "CWE-89: ...") and from references into a taxonomy named CWE.
func cwes(r result, desc *rule) []string {
	texts := slices.Clone([]string(r.Properties.Tags))
	refs := slices.Clone([]reference(r.Taxa))
	if desc != nil {
		texts = append(texts, desc.Properties.Tags...)
		for _, rel := range desc.Relationships {
			refs = append(refs, rel.Target)
		}
	}
	for _, ref := range refs {
		if strings.EqualFold(ref.ToolComponent.Name, "cwe") {
			texts = append(texts, "cwe-"+ref.ID)
		}
	}
	var out []string
	for _, t := range texts {
		m := cwePattern.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n <= maxCWENumber {
			out = append(out, "cwe-"+strconv.Itoa(n))
		}
	}
	return capSorted(out, maxCWEs)
}

// capSorted sorts, removes duplicates and keeps at most limit items.
func capSorted(items []string, limit int) []string {
	slices.Sort(items)
	items = slices.Compact(items)
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

// clip trims s, removes control characters (which could forge lines in a
// report) and caps its length on a rune boundary.
func clip(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, clipRaw(s, limit*2))
	return clipRaw(strings.TrimSpace(s), limit)
}

// clipLine is clip for one-line fields such as rule ids, titles and tags:
// every run of whitespace, line breaks included, becomes one space.
func clipLine(s string, limit int) string {
	return clipRaw(strings.Join(strings.Fields(clip(s, limit)), " "), limit)
}

// clipRaw caps s at limit bytes without splitting a rune and without adding
// a marker, so a clipped snippet is still a prefix of the original.
func clipRaw(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// finish orders findings deterministically and drops repeats of the same
// rule, file and line, keeping the most severe.
func (p *parser) finish() []finding.Finding {
	out := slices.Clone(p.out)
	slices.SortStableFunc(out, compareFindings)
	kept := out[:0]
	seen := map[string]bool{}
	for _, f := range out {
		if seen[f.ID] {
			p.stats.Duplicate++
			continue
		}
		seen[f.ID] = true
		kept = append(kept, f)
	}
	return kept
}

func compareFindings(a, b finding.Finding) int {
	if c := strings.Compare(a.Location.File, b.Location.File); c != 0 {
		return c
	}
	if a.Location.Line != b.Location.Line {
		return a.Location.Line - b.Location.Line
	}
	if c := strings.Compare(a.Source, b.Source); c != 0 {
		return c
	}
	if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
		return c
	}
	if a.Severity.Rank() != b.Severity.Rank() {
		return b.Severity.Rank() - a.Severity.Rank()
	}
	return strings.Compare(a.Description, b.Description)
}
