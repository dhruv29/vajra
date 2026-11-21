package har

import (
	"path"
	"slices"
	"strings"
)

// The rule below mirrors internal/crawl (changesState and its helpers), which
// decides which links a crawl must not follow. It is copied rather than
// shared so that the two packages stay independent; keep them in step.

// stateChangingWords name actions a GET to a badly designed application may
// still perform: with the operator's session it could log them out or destroy
// data in the application under test.
var stateChangingWords = []string{
	"logout", "log-out", "signout", "sign-out", "logoff", "delete", "remove", "destroy",
	"revoke", "unsubscribe", "deactivate", "disable", "reset", "purge", "cancel",
}

// wordSeparators split the words of a segment, key or value, so that
// "user_delete" and "logout.php" match but "presets" does not match "reset".
const wordSeparators = "-_.+~ "

// namesAction reports whether any path segment, query key or query value
// names one of stateChangingWords.
func namesAction(decodedPath string, queryParts []string) bool {
	parts := append(strings.Split(decodedPath, "/"), queryParts...)
	return slices.ContainsFunc(parts, namesStateChange)
}

// namesStateChange reports whether one part of a URL contains a
// stateChangingWords entry as whole words.
func namesStateChange(part string) bool {
	padded := "-" + words(part) + "-"
	return slices.ContainsFunc(stateChangingWords, func(word string) bool {
		return strings.Contains(padded, "-"+words(word)+"-")
	})
}

// words lower-cases text and writes every separator as "-".
func words(text string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(wordSeparators, r) {
			return '-'
		}
		return r
	}, strings.ToLower(text))
}

// staticExtensions are file types that are not worth seeding a crawler or
// scanner with: they hold no links and no endpoints, only bytes. The list
// matches internal/crawl.
var staticExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".css": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".pdf": true, ".zip": true, ".gz": true,
}

func isStaticAsset(decodedPath string) bool {
	return staticExtensions[strings.ToLower(path.Ext(decodedPath))]
}
