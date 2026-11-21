package har

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
)

const (
	// maxJSONDepth is how many levels of nested objects contribute field
	// names. Scanners inject into fields near the top; deeper ones add noise.
	maxJSONDepth = 4
	// maxJSONArrayItems is how many elements of one array are looked into
	// for field names; the elements of a list almost always share a shape.
	maxJSONArrayItems = 16
	formMediaType     = "application/x-www-form-urlencoded"
)

// bodyNames returns the sorted, distinct names of the body's parameters.
// Values are never kept; the values of secret-looking fields are remembered
// for the scrub. A body this package can not read yields no names.
func (b *builder) bodyNames(pd *harPostData, media string) []string {
	if pd == nil {
		return nil
	}
	if len(pd.Params) > 0 {
		return b.paramNames(pd.Params)
	}
	text := bodyText(pd)
	switch {
	case media == formMediaType:
		return b.paramNames(pairsToNameValues(splitPairs(text)))
	case isJSON(media):
		return b.jsonNames(text)
	}
	return nil
}

// bodyText returns the body, decoded when a proxy wrote it as base64. A body
// that does not decode is treated as absent.
func bodyText(pd *harPostData) string {
	if !strings.EqualFold(strings.TrimSpace(pd.Encoding), "base64") {
		return pd.Text
	}
	decoded, err := base64.StdEncoding.DecodeString(pd.Text)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func isJSON(media string) bool {
	return media == "application/json" || media == "text/json" || strings.HasSuffix(media, "+json")
}

func pairsToNameValues(pairs []pair) []nameValue {
	out := make([]nameValue, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, nameValue{Name: p.name, Value: p.value})
	}
	return out
}

func (b *builder) paramNames(params []nameValue) []string {
	names := make([]string, 0, len(params))
	for _, p := range params {
		if len(names) >= maxParams {
			break
		}
		if !validParamName(p.Name) {
			continue
		}
		if looksSecret(p.Name) {
			b.secrets.add(p.Value)
		}
		names = append(names, p.Name)
	}
	return sortedUnique(names)
}

// jsonNames returns the field names of a JSON body, nested ones written
// "parent.child". Text that is not JSON yields no names.
func (b *builder) jsonNames(text string) []string {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil
	}
	var names []string
	b.walkJSON("", value, 0, &names)
	return sortedUnique(names)
}

func (b *builder) walkJSON(prefix string, value any, depth int, names *[]string) {
	switch v := value.(type) {
	case map[string]any:
		b.walkObject(prefix, v, depth, names)
	case []any:
		for i, item := range v {
			if i >= maxJSONArrayItems {
				return
			}
			b.walkJSON(prefix, item, depth, names)
		}
	}
}

// walkObject records the keys of one object in sorted order, so that which
// names survive the maxParams cap does not depend on map order.
func (b *builder) walkObject(prefix string, object map[string]any, depth int, names *[]string) {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(*names) >= maxParams {
			return
		}
		name := key
		if prefix != "" {
			name = prefix + "." + key
		}
		if !validParamName(name) {
			continue
		}
		*names = append(*names, name)
		if secret, ok := object[key].(string); ok && looksSecret(key) {
			b.secrets.add(secret)
		}
		if depth+1 < maxJSONDepth {
			b.walkJSON(name, object[key], depth+1, names)
		}
	}
}

// sortedUnique returns a sorted copy of names without repeats.
func sortedUnique(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := append([]string(nil), names...)
	sort.Strings(out)
	unique := out[:1]
	for _, name := range out[1:] {
		if name != unique[len(unique)-1] {
			unique = append(unique, name)
		}
	}
	return unique
}
