// Package openapi reads an OpenAPI 3 description of an API and turns it into
// concrete requests to test.
//
// It only builds probe.Request values; sending them is the job of a
// probe.Fetcher, so nothing here opens a connection. Only JSON documents are
// read: the module has no YAML parser, and a YAML description converts to
// JSON without loss.
package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

const (
	// MaxDocumentBytes is the largest description that will be read.
	MaxDocumentBytes = 20 << 20

	supportedVersionPrefix = "3."
	pathParameter          = "path"
	queryParameter         = "query"
)

// methods are the path item fields that hold an operation.
var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Operation is one method on one path.
type Operation struct {
	// ID is the operationId, or "METHOD /path" when the description gives
	// none or repeats one.
	ID string `json:"id"`
	// Method is upper case.
	Method string `json:"method"`
	// Path is the template, for example /orders/{id}.
	Path    string `json:"path"`
	Summary string `json:"summary,omitempty"`
	// RequiresAuth is true when the operation (or the document default)
	// declares a non-empty security requirement.
	RequiresAuth bool `json:"requires_auth"`
	// PathParams are the names in the path template, in the order they appear.
	PathParams  []string `json:"path_params,omitempty"`
	QueryParams []Param  `json:"query_params,omitempty"`
	HasBody     bool     `json:"has_body"`
	// BodyExample is JSON, present when the description gives an example or
	// a schema simple enough to synthesise one from.
	BodyExample string `json:"body_example,omitempty"`

	// pathExamples holds the example values the description gives for path
	// parameters. It is not exported or serialised: an Operation that went
	// through JSON relies on RequestOptions.Params alone for path values.
	pathExamples map[string]string
}

// Param is one query parameter.
type Param struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Example  string `json:"example,omitempty"`
}

// Document is what Vajra uses of an API description.
type Document struct {
	Title   string   `json:"title"`
	Servers []string `json:"servers"`
	// Operations are sorted by path, then method.
	Operations []Operation `json:"operations"`
}

// Parse reads an OpenAPI 3.x JSON document. A YAML document is rejected with
// an error that says to convert it to JSON. Callbacks, links and webhooks are
// ignored: they describe requests the API makes, not ones it accepts.
func Parse(r io.Reader) (Document, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return Document{}, fmt.Errorf("openapi: read document: %w", err)
	}
	if len(raw) > MaxDocumentBytes {
		return Document{}, fmt.Errorf("openapi: the document is larger than the limit of %d MiB", MaxDocumentBytes>>20)
	}
	root, err := decode(raw)
	if err != nil {
		return Document{}, err
	}
	if err := checkVersion(root); err != nil {
		return Document{}, err
	}
	p := parser{root: root}
	return Document{
		Title:      text(object(root["info"])["title"]),
		Servers:    servers(root),
		Operations: p.operations(),
	}, nil
}

// decode reads the document as one JSON object. Numbers stay as written
// (json.Number) so an example of 42 is not turned into 4.2e+01 on the way out.
func decode(raw []byte) (map[string]any, error) {
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(raw) == 0 {
		return nil, errors.New("openapi: the document is empty")
	}
	if raw[0] != '{' {
		return nil, errors.New("openapi: the document is not JSON (it looks like YAML); convert it to JSON first")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("openapi: the document is not valid JSON: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("openapi: the document is not valid JSON: there is more after the first object")
	}
	return root, nil
}

func checkVersion(root map[string]any) error {
	if version := text(root["swagger"]); version != "" {
		return fmt.Errorf("openapi: this is a Swagger %s document; convert it to OpenAPI 3 first", version)
	}
	version, ok := root["openapi"].(string)
	switch {
	case !ok:
		return errors.New(`openapi: the document has no "openapi" version field; an OpenAPI 3 document is required`)
	case !strings.HasPrefix(version, supportedVersionPrefix):
		return fmt.Errorf("openapi: version %q is not supported; an OpenAPI 3 document is required", version)
	}
	return nil
}

func servers(root map[string]any) []string {
	urls := []string{}
	for _, server := range list(root["servers"]) {
		if serverURL := text(object(server)["url"]); serverURL != "" {
			urls = append(urls, serverURL)
		}
	}
	return urls
}

// parser reads operations out of a decoded document.
type parser struct {
	root map[string]any
}

// operations lists every operation, sorted by path then method, and gives
// each an ID no other operation has.
func (p parser) operations() []Operation {
	operations := []Operation{}
	for path, item := range object(p.root["paths"]) {
		if !strings.HasPrefix(path, "/") {
			continue // an extension field such as x-internal
		}
		pathItem := p.resolve(item)
		shared := list(pathItem["parameters"])
		for _, method := range methods {
			if raw, ok := pathItem[method].(map[string]any); ok {
				operations = append(operations, p.operation(path, method, raw, shared))
			}
		}
	}
	slices.SortFunc(operations, func(a, b Operation) int {
		if byPath := strings.Compare(a.Path, b.Path); byPath != 0 {
			return byPath
		}
		return strings.Compare(a.Method, b.Method)
	})
	return uniqueIDs(operations)
}

// uniqueIDs falls back to "METHOD /path" where an operationId is missing or
// already taken. The ID becomes a request ID, and responses are matched to
// requests by it.
func uniqueIDs(operations []Operation) []Operation {
	taken := map[string]bool{}
	for i, op := range operations {
		if op.ID == "" || taken[op.ID] {
			operations[i].ID = op.Method + " " + op.Path
		}
		taken[operations[i].ID] = true
	}
	return operations
}

func (p parser) operation(path, method string, raw map[string]any, shared []any) Operation {
	parameters := p.parameters(shared, list(raw["parameters"]))
	hasBody, bodyExample := p.body(raw)
	return Operation{
		ID:           text(raw["operationId"]),
		Method:       strings.ToUpper(method),
		Path:         path,
		Summary:      text(raw["summary"]),
		RequiresAuth: p.requiresAuth(raw),
		PathParams:   placeholders(path),
		QueryParams:  p.queryParams(parameters),
		HasBody:      hasBody,
		BodyExample:  bodyExample,
		pathExamples: p.pathExamples(parameters),
	}
}

// requiresAuth applies the security rules: an operation's own "security"
// replaces the document's, an empty list means public, and an empty
// requirement object ({}) in the list means that no credentials is one of the
// accepted alternatives.
func (p parser) requiresAuth(operation map[string]any) bool {
	declared, own := operation["security"]
	if !own {
		declared = p.root["security"]
	}
	requirements := list(declared)
	for _, requirement := range requirements {
		if len(object(requirement)) == 0 {
			return false
		}
	}
	return len(requirements) > 0
}

// parameters merges the parameters of a path with those of one operation.
// An operation's parameter replaces the path's when name and location match.
func (p parser) parameters(shared, own []any) []map[string]any {
	var merged []map[string]any
	index := map[string]int{}
	for _, raw := range slices.Concat(shared, own) {
		parameter := p.resolve(raw)
		name, in := text(parameter["name"]), text(parameter["in"])
		if name == "" {
			continue
		}
		key := in + "\x00" + name
		if at, seen := index[key]; seen {
			merged[at] = parameter
			continue
		}
		index[key] = len(merged)
		merged = append(merged, parameter)
	}
	return merged
}

func (p parser) queryParams(parameters []map[string]any) []Param {
	var params []Param
	for _, parameter := range parameters {
		if text(parameter["in"]) != queryParameter {
			continue
		}
		required, _ := parameter["required"].(bool)
		param := Param{Name: text(parameter["name"]), Required: required}
		if example, ok := p.parameterExample(parameter); ok {
			param.Example = stringify(example)
		}
		params = append(params, param)
	}
	slices.SortFunc(params, func(a, b Param) int { return strings.Compare(a.Name, b.Name) })
	return params
}

func (p parser) pathExamples(parameters []map[string]any) map[string]string {
	examples := map[string]string{}
	for _, parameter := range parameters {
		if text(parameter["in"]) != pathParameter {
			continue
		}
		if example, ok := p.parameterExample(parameter); ok {
			examples[text(parameter["name"])] = stringify(example)
		}
	}
	return examples
}

// body reports whether an operation takes a request body and gives a JSON
// example of one when the description allows.
func (p parser) body(operation map[string]any) (hasBody bool, example string) {
	declared, ok := operation["requestBody"]
	if !ok {
		return false, ""
	}
	media := jsonMedia(object(p.resolve(declared)["content"]))
	value, ok := p.mediaExample(media)
	if !ok {
		return true, ""
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return true, ""
	}
	return true, string(encoded)
}

// jsonMedia picks the media type object to take a body example from:
// application/json, else the first JSON-based type by name (such as
// application/merge-patch+json). Bodies in other formats get no example.
func jsonMedia(content map[string]any) map[string]any {
	if media, ok := content[jsonMediaType].(map[string]any); ok {
		return media
	}
	for _, name := range sortedKeys(content) {
		if strings.Contains(strings.ToLower(name), "json") {
			return object(content[name])
		}
	}
	return nil
}

// object returns v as a JSON object, or nil when it is anything else. Reading
// a key of nil is safe, so callers can walk a document without checking each
// step.
func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func text(v any) string {
	s, _ := v.(string)
	return s
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
