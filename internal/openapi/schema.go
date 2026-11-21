package openapi

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

const (
	// maxRefDepth is how many "$ref" hops are followed from one place. A
	// description whose references form a cycle stops here instead of looping.
	maxRefDepth = 16
	// maxSchemaDepth is how many levels of objects and arrays a synthesised
	// example may nest. It also ends schemas that contain themselves.
	maxSchemaDepth = 3
	// maxSchemaVisits is the work one Parse may spend expanding schemas, shared
	// by every operation. Depth limits alone do not bound it: allOf fan-out
	// and wide objects whose properties refer back multiply at every level, so
	// a small hostile document could otherwise keep Parse busy for hours. When
	// it runs out, bodies are left smaller or without an example.
	maxSchemaVisits = 100_000
	// maxExampleProperties is how many properties a synthesised object gets.
	// An example shows the shape of a body; it need not list every field.
	maxExampleProperties = 50

	localRefPrefix = "#/"
	jsonMediaType  = "application/json"

	exampleString = "string"
)

// resolve returns node as an object, following local references. It returns
// nil when node is not an object, a reference leads nowhere or outside the
// document, or the chain is longer than maxRefDepth.
func (p parser) resolve(node any) map[string]any {
	current := object(node)
	for range maxRefDepth {
		ref, isRef := current["$ref"].(string)
		if !isRef {
			return current
		}
		current = object(p.lookup(ref))
	}
	return nil
}

// lookup follows a JSON pointer such as "#/components/schemas/Order". Only
// references into this document are followed: fetching a remote one would
// mean a network request that no gate has seen.
func (p parser) lookup(ref string) any {
	if !strings.HasPrefix(ref, localRefPrefix) {
		return nil
	}
	var node any = p.root
	for _, token := range strings.Split(strings.TrimPrefix(ref, localRefPrefix), "/") {
		if unescaped, err := url.PathUnescape(token); err == nil {
			token = unescaped
		}
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		node = object(node)[token]
	}
	return node
}

// parameterExample finds a value for a parameter: its "example", the first of
// its "examples", or the example or default of its schema.
func (p parser) parameterExample(parameter map[string]any) (any, bool) {
	if value, ok := p.declaredExample(parameter); ok {
		return value, true
	}
	schema := p.resolve(parameter["schema"])
	for _, key := range []string{"example", "default"} {
		if value := schema[key]; value != nil {
			return value, true
		}
	}
	return nil, false
}

// mediaExample finds a body for a media type: an example the description
// gives, else one synthesised from the schema.
func (p parser) mediaExample(media map[string]any) (any, bool) {
	if value, ok := p.declaredExample(media); ok {
		return value, true
	}
	return p.synthesise(media["schema"], 1)
}

// declaredExample reads "example", or the first of "examples". JSON objects
// have no order once decoded, so "first" means first by name; that keeps the
// result the same from run to run.
func (p parser) declaredExample(holder map[string]any) (any, bool) {
	if value := holder["example"]; value != nil {
		return value, true
	}
	examples := object(holder["examples"])
	for _, name := range sortedKeys(examples) {
		if value := p.resolve(examples[name])["value"]; value != nil {
			return value, true
		}
	}
	return nil, false
}

// synthesise builds a small example value from a schema. It reports false
// when the schema is too vague or too deep to say anything about.
func (p parser) synthesise(node any, depth int) (any, bool) {
	if !p.spend(1) {
		return nil, false
	}
	schema := p.resolve(node)
	if schema == nil {
		return nil, false
	}
	for _, key := range []string{"example", "default"} {
		if value := schema[key]; value != nil {
			return value, true
		}
	}
	if choices := list(schema["enum"]); len(choices) > 0 {
		return choices[0], true
	}
	switch schemaType(schema) {
	case "string":
		return exampleString, true
	case "integer", "number":
		return 0, true
	case "boolean":
		return false, true
	case "array":
		return p.synthesiseArray(schema, depth)
	case "object":
		return p.synthesiseObject(schema, depth)
	}
	return nil, false
}

// schemaType names the type of a schema. OpenAPI 3.1 allows a list of types
// (["string", "null"]); the first that is not null is used. A schema that
// names no type is recognised by its shape.
func schemaType(schema map[string]any) string {
	if name := text(schema["type"]); name != "" {
		return name
	}
	for _, candidate := range list(schema["type"]) {
		if name := text(candidate); name != "" && name != "null" {
			return name
		}
	}
	switch {
	case schema["properties"] != nil || schema["allOf"] != nil:
		return "object"
	case schema["items"] != nil:
		return "array"
	}
	return ""
}

// synthesiseArray gives an array one item, or none when the item cannot be
// synthesised.
func (p parser) synthesiseArray(schema map[string]any, depth int) (any, bool) {
	if depth > maxSchemaDepth {
		return nil, false
	}
	if item, ok := p.synthesise(schema["items"], depth+1); ok {
		return []any{item}, true
	}
	return []any{}, true
}

// synthesiseObject fills in the properties that can be synthesised, at most
// maxExampleProperties of them, first by name so the example is the same from
// run to run. Read-only properties are left out, because a request must not
// send them.
func (p parser) synthesiseObject(schema map[string]any, depth int) (any, bool) {
	if depth > maxSchemaDepth {
		return nil, false
	}
	out := map[string]any{}
	properties := p.properties(schema, maxRefDepth)
	for _, name := range sortedKeys(properties) {
		if len(out) == maxExampleProperties {
			break
		}
		property := properties[name]
		if readOnly, _ := p.resolve(property)["readOnly"].(bool); readOnly {
			continue
		}
		if value, ok := p.synthesise(property, depth+1); ok {
			out[name] = value
		}
	}
	return out, true
}

// properties collects the properties of a schema and of the schemas it
// combines with allOf. budget bounds how deep allOf may nest; the shared
// work budget bounds how much is collected in all.
func (p parser) properties(schema map[string]any, budget int) map[string]any {
	out := map[string]any{}
	if budget == 0 || !p.spend(1+len(object(schema["properties"]))) {
		return out
	}
	for _, part := range list(schema["allOf"]) {
		for name, property := range p.properties(p.resolve(part), budget-1) {
			out[name] = property
		}
	}
	for name, property := range object(schema["properties"]) {
		out[name] = property
	}
	return out
}

// spend takes cost from the work budget of this Parse, and reports false,
// taking nothing, when there is not enough left.
func (p parser) spend(cost int) bool {
	if *p.work < cost {
		return false
	}
	*p.work -= cost
	return true
}

// stringify renders an example value the way it would be written in a URL.
func stringify(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}
