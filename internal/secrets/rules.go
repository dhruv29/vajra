package secrets

import (
	"regexp"

	"github.com/dhruv29/vajra/internal/finding"
)

const (
	privateKeyRuleID = "private-key"
	genericRuleID    = "generic-credential-assignment"
)

// rule is one kind of secret. When pattern has capture groups, the secret is
// the first group that took part in the match; otherwise it is the whole
// match.
type rule struct {
	id          string
	title       string
	description string
	severity    finding.Severity
	pattern     *regexp.Regexp
	// publicTag is true when the first characters of every match are a fixed
	// prefix the provider documents (AKIA, ghp_, xoxb, sk_l, AIza). Showing
	// them says which credential it is and nothing about its value.
	publicTag bool
}

// values returns where the rule's secrets are in text.
func (r *rule) values(text string) []span {
	var out []span
	for _, loc := range r.pattern.FindAllStringSubmatchIndex(text, -1) {
		value := span{start: loc[0], end: loc[1], tagged: r.publicTag}
		for group := 2; group+1 < len(loc); group += 2 {
			if loc[group] >= 0 {
				value = span{start: loc[group], end: loc[group+1], tagged: r.publicTag}
				break
			}
		}
		out = append(out, value)
	}
	return out
}

// providerRules match the fixed shape of one provider's credential. The
// shapes are distinctive enough that a match needs no entropy check.
var providerRules = []rule{
	{
		id:          "aws-access-key-id",
		title:       "AWS access key ID in source",
		description: "An AWS access key ID in source identifies a credential that anyone with the code can try to use; deactivate the key and load a new one from the environment or a secret manager.",
		severity:    finding.SeverityHigh,
		pattern:     regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		publicTag:   true,
	},
	{
		id:          "github-token",
		title:       "GitHub token in source",
		description: "A GitHub token in source gives anyone with the code the token's access to repositories; revoke it and load a new one from the environment or a secret manager.",
		severity:    finding.SeverityHigh,
		pattern:     regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{36,}\b`),
		publicTag:   true,
	},
	{
		id:          "slack-token",
		title:       "Slack token in source",
		description: "A Slack token in source lets anyone with the code read or post to the workspace; revoke it and load a new one from the environment or a secret manager.",
		severity:    finding.SeverityHigh,
		pattern:     regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`),
		publicTag:   true,
	},
	{
		id:          "stripe-secret-key",
		title:       "Stripe live secret key in source",
		description: "A Stripe live secret key in source lets anyone with the code act on the payment account; roll the key and load the new one from the environment or a secret manager.",
		severity:    finding.SeverityHigh,
		pattern:     regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,}\b`),
		publicTag:   true,
	},
	{
		id:          "google-api-key",
		title:       "Google API key in source",
		description: "A Google API key in source can be used by anyone with the code and billed to the project; restrict or regenerate the key and load it from the environment or a secret manager.",
		severity:    finding.SeverityHigh,
		// The key may end in "-", where \b does not hold, so the end is checked
		// by requiring a character that cannot belong to the key.
		pattern:   regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})(?:[^0-9A-Za-z_-]|$)`),
		publicTag: true,
	},
	{
		id:          privateKeyRuleID,
		title:       "Private key in source",
		description: "A private key in source lets anyone with the code impersonate its owner or decrypt its traffic; replace the key pair and keep the new private key out of the repository.",
		severity:    finding.SeverityHigh,
		// Whatever key material follows the header on the same line is part of
		// the match, so a key written as one string literal is masked whole.
		pattern: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+/=\s]|\\[nr])*(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)?`),
	},
	{
		id:          "jwt",
		title:       "JSON Web Token in source",
		description: "A JSON Web Token in source may be a live session or service credential for anyone with the code; invalidate it and obtain tokens at run time instead.",
		severity:    finding.SeverityHigh,
		// Header and payload are both JSON objects, which encode to "eyJ".
		pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	},
}

// credentialAssignment matches a value assigned to a credential-like name,
// quoted or not, with no entropy or placeholder checks. It reports nothing:
// it only decides what is masked in the context lines around a finding, where
// a credential no rule reports would otherwise be shown in full.
var credentialAssignment = regexp.MustCompile(`(?i)[a-z0-9_.-]*(?:passw(?:or)?d|pwd|pw|secret|token|api[_ .-]?key|access[_ .-]?key|private[_ .-]?key|auth|credentials?)[a-z0-9_-]*["']?` +
	`\s*(?::\s*[a-z_][a-z0-9_.]*\s*=|:=|=>|=|:)\s*` +
	`(?:"((?:[^"\\]|\\.){4,})"|'((?:[^'\\]|\\.){4,})'|(\S{4,}))`)

// genericRule matches a quoted value assigned to a name that says it is a
// credential, in the assignment forms of common languages and config files.
// Its matches are only reported after the placeholder and entropy checks.
var genericRule = rule{
	id:          genericRuleID,
	title:       "Hard-coded credential in source",
	description: "A value assigned to a credential-like name looks like a real secret, which anyone with the code can read; change the credential and load it from the environment or a secret manager.",
	severity:    finding.SeverityMedium,
	pattern: regexp.MustCompile(`(?i)[a-z0-9_.-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?key|credentials?)[a-z0-9_-]*["']?` +
		`\s*(?::\s*[a-z_][a-z0-9_.]*\s*=|:=|=>|=|:)\s*` +
		`(?:"((?:[^"\\]|\\.){8,})"|'((?:[^'\\]|\\.){8,})')`),
}
