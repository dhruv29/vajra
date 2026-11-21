package crawl

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// The extraction is deliberately tolerant and not a real HTML parser: pages
// found in the wild are often broken, and a missed link costs less than a
// crawl that gives up on a page. It looks only at the tags below.
var (
	commentPattern = regexp.MustCompile(`(?s)<!--.*?-->`)
	// The contents of script and style elements are removed first, so markup
	// that only exists inside a JavaScript string is not taken for a link.
	scriptBodyPattern = regexp.MustCompile(`(?is)(<script(?:[\s/][^>]*)?>).*?</script\s*>`)
	styleBodyPattern  = regexp.MustCompile(`(?is)(<style(?:[\s/][^>]*)?>).*?</style\s*>`)

	tagPattern = regexp.MustCompile(`(?is)<(/?)(a|link|area|iframe|script|form|base|input|select|textarea)((?:[\s/][^>]*)?)>`)
	// An attribute value may be double-quoted, single-quoted or bare.
	attributePattern = regexp.MustCompile(`(?s)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

// linkAttributes are the attributes that carry a URL on a link-bearing tag.
var linkAttributes = []string{"href", "src"}

// extraction is what one HTML document yields, before scope is applied.
type extraction struct {
	links []string // absolute, in document order, possibly repeated
	forms []Form
}

// tag is one start or end tag of interest.
type tag struct {
	name       string
	closing    bool
	attributes map[string]string
}

// extract finds the links and forms of an HTML document fetched from pageURL.
func extract(body string, pageURL *url.URL) extraction {
	tags := scan(body)
	base := documentBase(tags, pageURL)
	var out extraction
	var open *Form // the form whose fields are being collected
	closeForm := func() {
		if open != nil {
			out.forms = append(out.forms, finish(*open))
			open = nil
		}
	}
	for _, t := range tags {
		switch {
		case t.name == "form":
			closeForm()
			if !t.closing {
				open = openForm(t, base, pageURL)
			}
		case t.closing || t.name == "base":
		case t.name == "input" || t.name == "select" || t.name == "textarea":
			if name := t.attributes["name"]; open != nil && name != "" {
				open.Fields = append(open.Fields, name)
			}
		default:
			out.links = append(out.links, tagLinks(t, base)...)
		}
	}
	closeForm()
	// Only a GET form's action is a link. Fetching the action of a POST form
	// with the operator's session could submit it, or at least act on a route
	// meant to change state.
	for _, form := range out.forms {
		if form.Method == http.MethodGet {
			out.links = append(out.links, form.Action)
		}
	}
	return out
}

// scan lists the tags of interest in document order.
func scan(body string) []tag {
	body = commentPattern.ReplaceAllString(body, "")
	body = scriptBodyPattern.ReplaceAllString(body, "$1")
	body = styleBodyPattern.ReplaceAllString(body, "$1")
	matches := tagPattern.FindAllStringSubmatch(body, -1)
	tags := make([]tag, 0, len(matches))
	for _, match := range matches {
		tags = append(tags, tag{
			name: strings.ToLower(match[2]), closing: match[1] == "/", attributes: attributes(match[3]),
		})
	}
	return tags
}

// attributes reads the name="value" pairs of a tag. Names are lower-cased,
// values have their character references decoded (&amp; becomes &), and the
// first occurrence of a name wins, as it does in a browser.
func attributes(raw string) map[string]string {
	out := map[string]string{}
	for _, match := range attributePattern.FindAllStringSubmatch(raw, -1) {
		name := strings.ToLower(match[1])
		if _, seen := out[name]; seen {
			continue
		}
		out[name] = html.UnescapeString(match[2] + match[3] + match[4])
	}
	return out
}

// documentBase returns the URL that relative links resolve against: the first
// <base href> when there is a usable one, the page's own URL otherwise.
func documentBase(tags []tag, pageURL *url.URL) *url.URL {
	for _, t := range tags {
		if t.name != "base" || t.closing || t.attributes["href"] == "" {
			continue
		}
		if base, err := url.Parse(resolve(pageURL, t.attributes["href"])); err == nil && base.Host != "" {
			return base
		}
		break // only the first <base href> counts
	}
	return pageURL
}

func tagLinks(t tag, base *url.URL) []string {
	var links []string
	for _, attribute := range linkAttributes {
		if target := resolve(base, t.attributes[attribute]); target != "" {
			links = append(links, target)
		}
	}
	return links
}

// openForm starts a form. One without an action, or with only a fragment as
// its action, submits to the page itself.
// It returns nil when the action is not an http(s) URL, so the form and its
// fields are left out.
func openForm(t tag, base, pageURL *url.URL) *Form {
	action := pageURL.String()
	if raw := strings.TrimSpace(t.attributes["action"]); raw != "" && !strings.HasPrefix(raw, "#") {
		action = resolve(base, raw)
	}
	if action == "" {
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(t.attributes["method"]))
	if method == "" {
		method = http.MethodGet
	}
	return &Form{Action: action, Method: method, Fields: []string{}}
}

// finish sorts and de-duplicates the fields of a completed form.
func finish(form Form) Form {
	slices.Sort(form.Fields)
	form.Fields = slices.Compact(form.Fields)
	return form
}
