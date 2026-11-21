// Package blast estimates the blast radius of a finding: what an attacker
// could reach by exploiting it, and how sure we are of each step.
package blast

import (
	"regexp"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
)

// Capability is what exploiting a finding gives an attacker.
type Capability string

const (
	CodeExecution      Capability = "code_execution"
	DataAccess         Capability = "data_access"
	FileRead           Capability = "file_read"
	CredentialExposure Capability = "credential_exposure"
	AuthBypass         Capability = "auth_bypass"
	RequestForgery     Capability = "request_forgery"
	ClientSide         Capability = "client_side"
	InfoDisclosure     Capability = "info_disclosure"
	Misconfiguration   Capability = "misconfiguration"
	Unclassified       Capability = "unclassified"
)

// byPower lists capabilities from most to least powerful. When a finding
// matches several, the most powerful one decides its reach.
var byPower = []Capability{
	CodeExecution, DataAccess, FileRead, CredentialExposure, AuthBypass,
	RequestForgery, ClientSide, InfoDisclosure, Misconfiguration,
}

var cweCapabilities = map[string]Capability{
	"cwe-77": CodeExecution, "cwe-78": CodeExecution, "cwe-94": CodeExecution, "cwe-95": CodeExecution,
	"cwe-434": CodeExecution, "cwe-502": CodeExecution, "cwe-917": CodeExecution, "cwe-1336": CodeExecution,
	"cwe-89": DataAccess, "cwe-90": DataAccess, "cwe-564": DataAccess, "cwe-943": DataAccess,
	"cwe-22": FileRead, "cwe-23": FileRead, "cwe-36": FileRead, "cwe-73": FileRead, "cwe-98": FileRead, "cwe-611": FileRead,
	"cwe-256": CredentialExposure, "cwe-312": CredentialExposure, "cwe-321": CredentialExposure,
	"cwe-522": CredentialExposure, "cwe-798": CredentialExposure,
	"cwe-284": AuthBypass, "cwe-285": AuthBypass, "cwe-287": AuthBypass, "cwe-288": AuthBypass, "cwe-290": AuthBypass,
	"cwe-306": AuthBypass, "cwe-384": AuthBypass, "cwe-639": AuthBypass, "cwe-862": AuthBypass, "cwe-863": AuthBypass,
	"cwe-1390": AuthBypass,
	"cwe-918":  RequestForgery,
	"cwe-79":   ClientSide, "cwe-80": ClientSide, "cwe-352": ClientSide, "cwe-601": ClientSide, "cwe-1021": ClientSide,
	"cwe-200": InfoDisclosure, "cwe-209": InfoDisclosure, "cwe-215": InfoDisclosure, "cwe-497": InfoDisclosure,
	"cwe-532": InfoDisclosure, "cwe-538": InfoDisclosure, "cwe-540": InfoDisclosure, "cwe-548": InfoDisclosure,
	"cwe-16": Misconfiguration, "cwe-693": Misconfiguration, "cwe-732": Misconfiguration,
	"cwe-942": Misconfiguration, "cwe-1188": Misconfiguration,
}

var tagCapabilities = map[string]Capability{
	"rce": CodeExecution, "command-injection": CodeExecution, "ssti": CodeExecution,
	"deserialization": CodeExecution, "fileupload": CodeExecution, "file-upload": CodeExecution,
	"sqli": DataAccess, "nosqli": DataAccess, "sql-injection": DataAccess,
	"lfi": FileRead, "traversal": FileRead, "path-traversal": FileRead, "xxe": FileRead, "file-read": FileRead,
	"default-login": AuthBypass, "auth-bypass": AuthBypass, "unauth": AuthBypass, "idor": AuthBypass, "bola": AuthBypass,
	"ssrf": RequestForgery,
	"xss":  ClientSide, "csrf": ClientSide, "redirect": ClientSide, "open-redirect": ClientSide, "clickjacking": ClientSide,
	"token": CredentialExposure, "tokens": CredentialExposure, "secret": CredentialExposure, "secrets": CredentialExposure,
	"keys": CredentialExposure, "credentials": CredentialExposure, "creds": CredentialExposure,
	"exposure": InfoDisclosure, "disclosure": InfoDisclosure, "debug": InfoDisclosure, "logs": InfoDisclosure,
	"misconfig": Misconfiguration, "misconfiguration": Misconfiguration, "headers": Misconfiguration,
}

// credentialPattern recognises extracted values that look like live secrets.
var credentialPattern = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_ -]key|authorization)\s*[=:]\s*\S`)

// Classify decides what capability a finding represents and says what the
// decision was based on. The scanner's CWE is trusted first, then its tags.
func Classify(f finding.Finding) (Capability, string) {
	capability, basis := Unclassified, "the scanner gave no CWE or recognised tag, so only the affected asset is counted"
	if c, key := strongest(f.CWE, cweCapabilities); c != Unclassified {
		capability, basis = c, "scanner classification "+strings.ToUpper(key)
	} else if c, key := strongest(f.Tags, tagCapabilities); c != Unclassified {
		capability, basis = c, "scanner tag \""+key+"\""
	}
	if exposesCredentials(f) && power(CredentialExposure) < power(capability) {
		return CredentialExposure, "values in the response look like credentials (taken from the target's own output, so unverified)"
	}
	return capability, basis
}

// strongest returns the most powerful capability any key maps to.
func strongest(keys []string, table map[string]Capability) (Capability, string) {
	best, bestKey := Unclassified, ""
	for _, raw := range keys {
		key := strings.ToLower(strings.TrimSpace(raw))
		if c, ok := table[key]; ok && power(c) < power(best) {
			best, bestKey = c, key
		}
	}
	return best, bestKey
}

// power is a capability's position in byPower; lower is more powerful.
func power(c Capability) int {
	for i, candidate := range byPower {
		if candidate == c {
			return i
		}
	}
	return len(byPower)
}

func exposesCredentials(f finding.Finding) bool {
	for _, value := range f.Evidence.Extracted {
		if credentialPattern.MatchString(value) {
			return true
		}
	}
	return false
}
