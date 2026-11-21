package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
)

// The subset of SARIF 2.1.0 that Vajra reads. Every list that a hostile file
// could make enormous is decoded through a capped type, so memory stays
// proportional to what is kept, not to what was sent.

const (
	// maxRules bounds tool.driver.rules. Real tools ship a few thousand at most.
	maxRules = 20000
	// maxListItems bounds the small lists inside one result or rule (locations,
	// tags, taxa, relationships, suppressions).
	maxListItems = 64
	// maxBaseIDs bounds run.originalUriBaseIds.
	maxBaseIDs = 64
)

type toolInfo struct {
	Driver struct {
		Name  string   `json:"name"`
		Rules ruleList `json:"rules"`
	} `json:"driver"`
}

type message struct {
	Text string `json:"text"`
}

type rule struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	ShortDescription     message `json:"shortDescription"`
	FullDescription      message `json:"fullDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties    properties              `json:"properties"`
	Relationships smallList[relationship] `json:"relationships"`
}

type properties struct {
	Tags             smallList[string] `json:"tags"`
	SecuritySeverity score             `json:"security-severity"`
}

// reference is a SARIF reportingDescriptorReference: a pointer into a
// taxonomy such as CWE.
type reference struct {
	ID            string `json:"id"`
	ToolComponent struct {
		Name string `json:"name"`
	} `json:"toolComponent"`
}

type relationship struct {
	Target reference `json:"target"`
}

type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type region struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
	Snippet   struct {
		Text string `json:"text"`
	} `json:"snippet"`
}

type location struct {
	PhysicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region           region           `json:"region"`
	} `json:"physicalLocation"`
}

type suppression struct {
	Status string `json:"status"`
}

type ruleRef struct {
	ID    string `json:"id"`
	Index *int   `json:"index"`
}

type result struct {
	RuleID        string                 `json:"ruleId"`
	RuleIndex     *int                   `json:"ruleIndex"`
	Rule          ruleRef                `json:"rule"`
	Kind          string                 `json:"kind"`
	Level         string                 `json:"level"`
	BaselineState string                 `json:"baselineState"`
	Message       message                `json:"message"`
	Locations     smallList[location]    `json:"locations"`
	Suppressions  smallList[suppression] `json:"suppressions"`
	Taxa          smallList[reference]   `json:"taxa"`
	Properties    properties             `json:"properties"`
}

// suppressed follows SARIF §3.27.23: a suppression counts unless a reviewer
// rejected it or it is still under review. An empty list means "checked, not
// suppressed".
func (r result) suppressed() bool {
	for _, s := range r.Suppressions {
		if s.Status == "" || s.Status == "accepted" {
			return true
		}
	}
	return false
}

// excluded reports results that are not open failures: suppressed, fixed
// since the baseline, or a kind (pass, review, informational...) that is not
// a claim of a problem.
func (r result) excluded() bool {
	return r.suppressed() || r.BaselineState == "absent" || (r.Kind != "" && r.Kind != "fail")
}

// smallList decodes a JSON array, keeping at most maxListItems elements. Any
// other shape, or an element of the wrong shape, is ignored rather than fatal.
type smallList[T any] []T

func (l *smallList[T]) UnmarshalJSON(raw []byte) error {
	*l = decodeCapped[T](raw, maxListItems)
	return nil
}

type ruleList []rule

func (l *ruleList) UnmarshalJSON(raw []byte) error {
	*l = decodeCapped[rule](raw, maxRules)
	return nil
}

// decodeCapped reads up to limit elements of a JSON array and stops; the rest
// is never decoded. An element with a wrongly typed field keeps the fields
// that did decode.
func decodeCapped[T any](raw []byte, limit int) []T {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil
	}
	var out []T
	for len(out) < limit && dec.More() {
		var item T
		if err := dec.Decode(&item); err != nil && !isTypeError(err) {
			return out
		}
		out = append(out, item)
	}
	return out
}

// baseIDs is run.originalUriBaseIds, capped.
type baseIDs map[string]artifactLocation

func (m *baseIDs) UnmarshalJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	out := baseIDs{}
	for len(out) < maxBaseIDs && dec.More() {
		tok, err := dec.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey {
			break
		}
		var loc artifactLocation
		if err := dec.Decode(&loc); err != nil && !isTypeError(err) {
			break
		}
		out[key] = loc
	}
	*m = out
	return nil
}

// score is a CVSS-like 0–10 number that tools write either as a JSON number
// or as a string ("8.8", as CodeQL does).
type score struct {
	value float64
	ok    bool
}

const maxScore = 10

func (s *score) UnmarshalJSON(raw []byte) error {
	if string(raw) == "null" {
		return nil
	}
	var n float64
	if json.Unmarshal(raw, &n) != nil {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return nil
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil {
			return nil
		}
		n = parsed
	}
	if math.IsNaN(n) || n < 0 || n > maxScore {
		return nil
	}
	*s = score{value: n, ok: true}
	return nil
}

func isTypeError(err error) bool {
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &typeErr)
}
