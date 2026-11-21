package inject

import (
	"strings"

	"github.com/dhruv29/vajra/internal/probe"
)

const (
	// markerPrefix starts every reflection marker, so a person reading a
	// response can spot it.
	markerPrefix = "vj"
	// maxEncodedLen is the longest form one metacharacter may take after an
	// application encodes it (for example "&#x00022;" or """). It bounds
	// how far apart two copies of the marker may be and still belong to one
	// reflection.
	maxEncodedLen = 10
	// markerCopies is how many times the marker appears in the payload.
	markerCopies = 4
)

// Reflection contexts, as written into evidence.
const (
	ctxText     = "html-text"
	ctxScript   = "script-block"
	ctxDouble   = "double-quoted-attribute"
	ctxSingle   = "single-quoted-attribute"
	ctxUnquoted = "unquoted-attribute"
	ctxComment  = "html-comment"
)

// xssPayload puts each character that matters between two copies of the
// marker: M"M'M<M>. Each character can then be checked on its own, so an
// application that encodes some characters but not others is judged exactly,
// and "<M>" is a real start tag if it comes back raw.
func xssPayload(marker string) string {
	return marker + `"` + marker + `'` + marker + `<` + marker + `>`
}

// reflection is where a payload came back and what that proves.
type reflection struct {
	context string
	// at is the byte offset of the reflection in the body.
	at int
}

// findReflection applies the reflected-input proof rule: the response is
// HTML from the target, and somewhere the payload comes back with the
// character that breaks out of the context it landed in unencoded. In text
// that is "<" (a new tag); in a double- or single-quoted attribute it is the
// matching quote; in an unquoted attribute both ">" and "<". A reflection in
// a comment, or one that is fully encoded, proves nothing and is ignored.
func findReflection(r probe.Response, marker string) (reflection, bool) {
	if !r.Answered() || !isHTML(r) {
		return reflection{}, false
	}
	body := r.Body
	for from := 0; from < len(body); {
		i := strings.Index(body[from:], marker)
		if i < 0 {
			break
		}
		at := from + i
		from = at + len(marker)
		if continuesReflection(body, at, marker) {
			continue
		}
		ctx := contextAt(body[:at])
		region := body[at:min(len(body), at+regionLen(marker))]
		if breaksOut(ctx, region, marker) {
			return reflection{context: ctx, at: at}, true
		}
	}
	return reflection{}, false
}

// regionLen is how many bytes one reflection of the payload can span, with
// every metacharacter encoded in its longest form.
func regionLen(marker string) int {
	return markerCopies * (len(marker) + maxEncodedLen)
}

// continuesReflection reports whether the marker at offset at is a later copy
// within a reflection (another copy ends just before it). Its context is then
// coloured by the payload itself and only the first copy is judged.
func continuesReflection(body string, at int, marker string) bool {
	window := body[max(0, at-len(marker)-maxEncodedLen):at]
	return strings.Contains(window, marker)
}

// breaksOut reports whether region, a reflection starting in ctx, carries the
// raw character that escapes ctx.
func breaksOut(ctx, region, marker string) bool {
	switch ctx {
	case ctxText, ctxScript:
		return strings.Contains(region, marker+"<"+marker)
	case ctxDouble:
		return strings.Contains(region, marker+`"`+marker)
	case ctxSingle:
		return strings.Contains(region, marker+"'"+marker)
	case ctxUnquoted:
		return strings.Contains(region, marker+"<"+marker+">")
	}
	return false
}

// contextAt is a cheap guess at where in the document the text after prefix
// lies. It is not a parser: an attribute value holding ">" can fool it, which
// only ever makes the rule stricter or names the wrong context in evidence,
// because every context still demands a raw breakout character.
func contextAt(prefix string) string {
	lt, gt := strings.LastIndex(prefix, "<"), strings.LastIndex(prefix, ">")
	if lt <= gt {
		lower := strings.ToLower(prefix)
		if strings.LastIndex(lower, "<script") > strings.LastIndex(lower, "</script") {
			return ctxScript
		}
		return ctxText
	}
	if strings.HasPrefix(prefix[lt:], "<!--") {
		return ctxComment
	}
	return quoteState(prefix[lt:])
}

// quoteState follows the quotes inside an open tag to tell which kind of
// attribute value, if any, the tag ends in.
func quoteState(tag string) string {
	var open rune
	for _, r := range tag {
		switch {
		case open == 0 && (r == '"' || r == '\''):
			open = r
		case r == open:
			open = 0
		}
	}
	switch open {
	case '"':
		return ctxDouble
	case '\'':
		return ctxSingle
	}
	return ctxUnquoted
}

// isHTML reports whether a response says it is an HTML document. A
// reflection in JSON or plain text is not rendered as markup by a browser.
func isHTML(r probe.Response) bool {
	mediaType, _, _ := strings.Cut(header(r, "Content-Type"), ";")
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "text/html", "application/xhtml+xml":
		return true
	}
	return false
}

// header returns the first value of a response header. Names are compared
// without regard to case because the map may come from JSON, not net/http.
func header(r probe.Response, name string) string {
	for key, values := range r.Headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
