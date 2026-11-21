package secrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dhruv29/vajra/internal/finding"
)

// The fake credentials below are assembled at run time, so that no complete
// credential-shaped literal sits in this file for a scanner to report.
var (
	fakeAWSKey     = "AKIA" + "IOSFODNN7" + "EXAMPLX"
	fakeGitHub     = "ghp" + "_" + strings.Repeat("aB3dE6gH9", 4)
	fakeGitHubPAT  = "github" + "_pat_" + strings.Repeat("aB3dE6gH9_", 4)
	fakeSlack      = "xox" + "b-" + "123456789012-" + "abcdefABCDEF"
	fakeStripe     = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	fakeGoogle     = "AI" + "za" + strings.Repeat("Sy0aB3d", 5)
	fakeJWT        = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	fakePassword   = "s3cr3t-" + "Hunter42!"
	fakeKeyHeader  = "-----BEGIN RSA " + "PRIVATE KEY-----"
	fakeKeyFooter  = "-----END RSA " + "PRIVATE KEY-----"
	fakeKeyBody    = []string{"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "BKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj", "Zm9v"}
	fakePEM        = fakeKeyHeader + "\n" + strings.Join(fakeKeyBody, "\n") + "\n" + fakeKeyFooter
	passwordAssign = "password = " + quoted(fakePassword)
)

func quoted(value string) string { return `"` + value + `"` }

// writeTree creates the files under a new temporary directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func mustScan(t *testing.T, root string) []finding.Finding {
	t.Helper()
	findings, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return findings
}

func scanContent(t *testing.T, content string) []finding.Finding {
	t.Helper()
	return mustScan(t, writeTree(t, map[string]string{"app.txt": content}))
}

func ruleIDs(findings []finding.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func targets(findings []finding.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Target)
	}
	return out
}

func TestScanMatchesEachRuleAndOnlyThatRule(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string // rule IDs; nil when the line is not a secret
	}{
		{"aws long-term key", "aws = " + quoted(fakeAWSKey), []string{"aws-access-key-id"}},
		{"aws temporary key", "id: AS" + "IA" + fakeAWSKey[4:], []string{"aws-access-key-id"}},
		{"aws key one character short", "aws = " + quoted(fakeAWSKey[:19]), nil},
		{"aws key one character long", "aws = " + quoted(fakeAWSKey+"Q"), nil},
		{"aws key in lower case", "aws = " + quoted("AKIA"+strings.ToLower(fakeAWSKey[4:])), nil},

		{"github personal token", "gh = " + quoted(fakeGitHub), []string{"github-token"}},
		{"github server token", "gh = " + quoted("ghs"+fakeGitHub[3:]), []string{"github-token"}},
		{"github fine-grained token", "gh = " + quoted(fakeGitHubPAT), []string{"github-token"}},
		{"github token too short", "gh = " + quoted(fakeGitHub[:39]), nil},
		{"github unknown prefix", "gh = " + quoted("ghx"+fakeGitHub[3:]), nil},

		{"slack bot token", "slack = " + quoted(fakeSlack), []string{"slack-token"}},
		{"slack user token", "slack = " + quoted("xox"+"p-"+fakeSlack[5:]), []string{"slack-token"}},
		{"slack unknown kind", "slack = " + quoted("xox"+"z-"+fakeSlack[5:]), nil},
		{"slack prefix alone", "slack = " + quoted("xox"+"b-short"), nil},

		{"stripe live key", "stripe = " + quoted(fakeStripe), []string{"stripe-secret-key"}},
		{"stripe non-live key", "stripe = " + quoted("sk"+"_demo_"+fakeStripe[8:]), nil},
		{"stripe publishable key", "stripe = " + quoted("pk"+fakeStripe[2:]), nil},

		{"google api key", "maps = " + quoted(fakeGoogle), []string{"google-api-key"}},
		{"google api key at end of line", "maps = " + fakeGoogle, []string{"google-api-key"}},
		{"google key one character short", "maps = " + quoted(fakeGoogle[:38]), nil},
		{"google key one character long", "maps = " + quoted(fakeGoogle+"Q"), nil},

		{"private key header", fakeKeyHeader, []string{"private-key"}},
		{"unlabelled private key header", "-----BEGIN " + "PRIVATE KEY-----", []string{"private-key"}},
		{"openssh private key header", "-----BEGIN OPENSSH " + "PRIVATE KEY-----", []string{"private-key"}},
		{"pgp private key block", "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----", []string{"private-key"}},
		{"public key header", "-----BEGIN PUBLIC KEY-----", nil},
		{"certificate header", "-----BEGIN CERTIFICATE-----", nil},

		{"jwt", "auth = " + quoted(fakeJWT), []string{"jwt"}},
		{"jwt with two segments", "auth = " + quoted(fakeJWT[:strings.LastIndex(fakeJWT, ".")]), nil},
		{"jwt whose payload is not an object", "auth = " + quoted(strings.Replace(fakeJWT, ".ey"+"J", ".abc", 1)), nil},

		{"generic double-quoted assignment", passwordAssign, []string{"generic-credential-assignment"}},
		{"generic single-quoted yaml value", "api_key: '" + fakePassword + "'", []string{"generic-credential-assignment"}},
		{"generic shell assignment", "SECRET_TOKEN=" + quoted(fakePassword), []string{"generic-credential-assignment"}},
		{"generic json member", `"client_secret": ` + quoted(fakePassword), []string{"generic-credential-assignment"}},
		{"generic annotated assignment", "db_password: str = " + quoted(fakePassword), []string{"generic-credential-assignment"}},
		{"generic short declaration", "apiKey := " + quoted(fakePassword), []string{"generic-credential-assignment"}},
		{"generic hash rocket", "'passwd' => '" + fakePassword + "'", []string{"generic-credential-assignment"}},
		{"generic value with an escaped quote", `token = "` + fakePassword + `\"tail"`, []string{"generic-credential-assignment"}},
		{"generic value of seven characters", `password = "s3cr3t!"`, nil},
		{"generic unquoted value", "password = " + fakePassword, nil},
		{"generic name that is not a credential", "username = " + quoted(fakePassword), nil},
		{"generic comparison is not an assignment", "if password == " + quoted(fakePassword), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanContent(t, tc.line+"\n")

			if got := ruleIDs(findings); !slices.Equal(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScanFillsEveryFindingField(t *testing.T) {
	findings := scanContent(t, "first\naws = "+quoted(fakeAWSKey)+"\n"+passwordAssign+"\n")

	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	aws, generic := findings[0], findings[1]
	if aws.Kind != finding.Static || aws.Source != Source || aws.RuleID != "aws-access-key-id" ||
		aws.Title != "AWS access key ID in source" || aws.Description == "" ||
		aws.Severity != finding.SeverityHigh || aws.Target != "app.txt:2" || aws.Status != finding.Candidate {
		t.Fatalf("finding = %+v", aws)
	}
	if aws.ID != finding.StableID(Source, "aws-access-key-id", "app.txt:2", "") {
		t.Fatalf("id = %q", aws.ID)
	}
	if *aws.Location != (finding.Location{File: "app.txt", Line: 2, EndLine: 2}) {
		t.Fatalf("location = %+v", *aws.Location)
	}
	if !slices.Equal(aws.CWE, []string{"cwe-798"}) || !slices.Equal(aws.Tags, []string{"secrets"}) {
		t.Fatalf("cwe = %v, tags = %v", aws.CWE, aws.Tags)
	}
	if !slices.Equal(aws.Evidence.Extracted, []string{"AKIA…[masked 16 chars]"}) {
		t.Fatalf("extracted = %v", aws.Evidence.Extracted)
	}
	if generic.Severity != finding.SeverityMedium || generic.Target != "app.txt:3" {
		t.Fatalf("generic finding = %+v", generic)
	}
}

func TestScanSuppressesPlaceholderValues(t *testing.T) {
	values := []string{
		"example-key-12345", "ChangeMe123!", "change-me-now-9f", "placeholder-9f8e", "your_api_key_here",
		"yourkey-9f8e7d6c", "xxxxxxxx1234abcd", "dummy-value-91ab", "unit-test-token-8842", "sample-9f8e7d6c",
		"REDACTED-9f8e7d", "<api-key-goes-here>", "${DB_PASSWORD_9f}", "{{ vault.db_pass }}", "prefix-%s-9f8e7d",
		"aaaaaaaaaaaa", "££££££££££", "os.environ['DB_PASS_9f']", "process.env.DB_PASS_9f", "$(getenv DB_PASS_9f)",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			findings := scanContent(t, "password = "+quoted(value)+"\n")

			if len(findings) != 0 {
				t.Fatalf("rules = %v, want none", ruleIDs(findings))
			}
		})
	}
}

func TestScanDoesNotApplyPlaceholderWordsToProviderRules(t *testing.T) {
	findings := scanContent(t, "key = "+quoted("AKIA"+"TESTSAMPLE"+"DUMMY0")+"\n")

	if !slices.Equal(ruleIDs(findings), []string{"aws-access-key-id"}) {
		t.Fatalf("rules = %v", ruleIDs(findings))
	}
}

func TestScanReportsGenericValuesOnlyAboveTheEntropyThreshold(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  int
	}{
		{"eight distinct characters are exactly at the threshold", "abcdefgh", 0},
		{"nine distinct characters are above it", "abcdefghi", 1},
		{"a long value of few characters is below it", "abababababababab", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanContent(t, "password = "+quoted(tc.value)+"\n")

			if len(findings) != tc.want {
				t.Fatalf("findings = %d, want %d (entropy %v)", len(findings), tc.want, shannonEntropy(tc.value))
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		value string
		want  float64
	}{
		{"", 0}, {"aaaa", 0}, {"abab", 1}, {"abcd", 2}, {"abcdefgh", minEntropy},
	}
	for _, tc := range cases {
		if got := shannonEntropy(tc.value); got != tc.want {
			t.Errorf("shannonEntropy(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestMask(t *testing.T) {
	cases := []struct{ value, want string }{
		{"abcdefghij", "abcd…[masked 6 chars]"},
		{"abcde", "abcd…[masked 1 chars]"},
		{"abcd", "…[masked 4 chars]"},
		{"", "…[masked 0 chars]"},
		{"pässwörd", "päss…[masked 4 chars]"},
	}
	for _, tc := range cases {
		if got := mask(tc.value); got != tc.want {
			t.Errorf("mask(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

func TestScanNeverPutsASecretInAFinding(t *testing.T) {
	// Arrange: every kind of secret close together, so each one also falls in
	// the context lines of its neighbours.
	secrets := []string{fakeAWSKey, fakeGitHub, fakeGitHubPAT, fakeSlack, fakeStripe, fakeGoogle, fakeJWT, fakePassword}
	ignored := "sk" + "_live_" + "9zY8xW7vU6tS5rQ4pO3nM2lK"
	oneLineKey := fakeKeyHeader + `\n` + strings.Join(fakeKeyBody, `\n`) + `\n` + fakeKeyFooter
	lines := []string{
		"aws = " + quoted(fakeAWSKey) + " # backup " + fakeAWSKey,
		"gh = " + quoted(fakeGitHub),
		"pat = " + quoted(fakeGitHubPAT),
		"slack = " + quoted(fakeSlack),
		"stripe = " + quoted(fakeStripe),
		"old = " + quoted(ignored) + " # " + ignoreMarker,
		"maps = " + quoted(fakeGoogle),
		"token = " + quoted(fakeJWT),
		passwordAssign,
		"pem = " + quoted(oneLineKey),
		fakePEM,
		"done",
	}
	root := writeTree(t, map[string]string{"config/settings.py": strings.Join(lines, "\n")})

	// Act
	findings := mustScan(t, root)
	encoded, err := json.Marshal(findings)

	// Assert
	if err != nil || len(findings) != 10 {
		t.Fatalf("findings = %d (%v), err = %v; want 10", len(findings), ruleIDs(findings), err)
	}
	text := string(encoded)
	for _, secret := range append(secrets, ignored, fakeKeyBody[0], fakeKeyBody[1], fakeKeyBody[2]) {
		if strings.Contains(text, secret) {
			t.Errorf("the findings contain the secret %q", secret)
		}
	}
	for _, f := range findings {
		if !strings.Contains(f.Evidence.Code, "…[masked ") || len(f.Evidence.Extracted) != 1 ||
			!strings.Contains(f.Evidence.Extracted[0], "…[masked ") {
			t.Errorf("%s: evidence is not masked: %+v", f.Target, f.Evidence)
		}
	}
}

func TestScanMasksAKeyBodyThatHasNoEndLine(t *testing.T) {
	body := strings.Repeat("Qm9keUxpbmVPZktleU1hdGVyaWFs\n", maxKeyBodyLines+2)

	findings := scanContent(t, fakeKeyHeader+"\n"+body+passwordAssign+"\n")

	if !slices.Equal(targets(findings), []string{"app.txt:1", "app.txt:68"}) {
		t.Fatalf("targets = %v", targets(findings))
	}
	if strings.Contains(findings[0].Evidence.Code, "Qm9keUxpbmVP") {
		t.Fatalf("key body is shown:\n%s", findings[0].Evidence.Code)
	}
}

func TestScanShowsNumberedContextWithTheReportedLineMarked(t *testing.T) {
	content := "one\ntwo\nthree\nfour\n" + passwordAssign + "\nsix\nseven\neight\nnine\n"
	want := "      2 | two\n" +
		"      3 | three\n" +
		"      4 | four\n" +
		">     5 | password = \"s3cr…[masked 12 chars]\"\n" +
		"      6 | six\n" +
		"      7 | seven\n" +
		"      8 | eight\n"

	findings := scanContent(t, content)

	if len(findings) != 1 || findings[0].Evidence.Code != want {
		t.Fatalf("code =\n%s\nwant\n%s", findings[0].Evidence.Code, want)
	}
}

func TestScanTruncatesLongContextLines(t *testing.T) {
	long := strings.Repeat("é", maxLineChars)

	findings := scanContent(t, passwordAssign+"\n"+long+"\n")

	wantLine := "      2 | " + strings.Repeat("é", maxLineChars/2) + " [line truncated]\n"
	if len(findings) != 1 || !strings.HasSuffix(findings[0].Evidence.Code, wantLine) {
		t.Fatalf("code = %q", findings[0].Evidence.Code)
	}
}

func TestScanFindsSecretsOnTheFirstAndLastLine(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"no trailing newline", "k = " + quoted(fakeAWSKey) + "\nmiddle\n" + passwordAssign},
		{"windows line endings", "k = " + quoted(fakeAWSKey) + "\r\nmiddle\r\n" + passwordAssign + "\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanContent(t, tc.content)

			if !slices.Equal(targets(findings), []string{"app.txt:1", "app.txt:3"}) {
				t.Fatalf("targets = %v", targets(findings))
			}
			last := findings[1].Evidence.Code
			if !strings.Contains(last, ">     3 | password") || strings.Contains(last, "\r") {
				t.Fatalf("code = %q", last)
			}
		})
	}
}

func TestScanReportsEachRuleOncePerLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string
	}{
		{"the same rule twice", fakeAWSKey + " " + "ASIA" + fakeAWSKey[4:], []string{"aws-access-key-id"}},
		{"two rules on different spans", fakeAWSKey + " " + fakeGitHub, []string{"aws-access-key-id", "github-token"}},
		{"provider rule wins over the generic rule", "token = " + quoted(fakeJWT), []string{"jwt"}},
		{"provider rule wins inside a longer value", "secret = " + quoted("Bearer "+fakeGitHub), []string{"github-token"}},
		{"two generic assignments", passwordAssign + "; " + passwordAssign, []string{"generic-credential-assignment"}},
		{"generic and provider on separate values", passwordAssign + "; k = " + quoted(fakeAWSKey),
			[]string{"aws-access-key-id", "generic-credential-assignment"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanContent(t, tc.line+"\n")

			if !slices.Equal(ruleIDs(findings), tc.want) {
				t.Fatalf("rules = %v, want %v", ruleIDs(findings), tc.want)
			}
			if strings.Contains(findings[0].Evidence.Code, "Bearer") {
				t.Fatalf("the rest of the quoted value is shown: %q", findings[0].Evidence.Code)
			}
		})
	}
}

func TestScanSkipsLinesWithTheIgnoreMarker(t *testing.T) {
	content := "k = " + quoted(fakeAWSKey) + " # " + ignoreMarker + "\n" +
		passwordAssign + " // " + ignoreMarker + "\n" +
		fakeKeyHeader + " " + ignoreMarker + "\n" +
		"k2 = " + quoted(fakeAWSKey) + "\n"

	findings := scanContent(t, content)

	if !slices.Equal(targets(findings), []string{"app.txt:4"}) {
		t.Fatalf("targets = %v", targets(findings))
	}
}

func TestScanSkipsDependencyAndBuildDirectories(t *testing.T) {
	line := "k = " + quoted(fakeAWSKey) + "\n"
	files := map[string]string{"src/app.txt": line, "src/builder/app.txt": line}
	for dir := range skippedDirs {
		files[dir+"/creds.txt"] = line
		files["src/"+dir+"/deep/creds.txt"] = line
	}
	root := writeTree(t, files)

	findings := mustScan(t, root)

	if !slices.Equal(targets(findings), []string{"src/app.txt:1", "src/builder/app.txt:1"}) {
		t.Fatalf("targets = %v", targets(findings))
	}
}

func TestScanSkipsBinaryOversizedAndEmptyFiles(t *testing.T) {
	line := "k = " + quoted(fakeAWSKey) + "\n"
	root := writeTree(t, map[string]string{
		"binary.dat":   line + "\x00\x01\x02",
		"huge.txt":     line + strings.Repeat("a", maxFileBytes),
		"at-limit.txt": line + strings.Repeat("a", maxFileBytes-len(line)),
		"empty.txt":    "",
		// A NUL byte past the sniffed prefix does not make a file binary.
		"late-nul.txt": line + strings.Repeat("a", binarySniffBytes) + "\x00",
	})

	findings := mustScan(t, root)

	if !slices.Equal(targets(findings), []string{"at-limit.txt:1", "late-nul.txt:1"}) {
		t.Fatalf("targets = %v", targets(findings))
	}
}

func TestScanDoesNotFollowLinksOutOfTheTree(t *testing.T) {
	// Arrange
	line := "k = " + quoted(fakeAWSKey) + "\n"
	outside := writeTree(t, map[string]string{"creds.txt": line})
	root := writeTree(t, map[string]string{"readme.txt": "nothing here\n"})
	if err := os.Symlink(filepath.Join(outside, "creds.txt"), filepath.Join(root, "leak.txt")); err != nil {
		t.Skipf("symbolic links are not available: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}

	// Act
	findings := mustScan(t, root)

	// Assert
	if len(findings) != 0 {
		t.Fatalf("content outside the tree was read: %v", targets(findings))
	}
	for _, file := range []string{"leak.txt", "linked/creds.txt"} {
		f := finding.Finding{RuleID: "aws-access-key-id", Location: &finding.Location{File: file, Line: 1}}
		if ok, err := Reproduce(root, f); ok || err == nil {
			t.Errorf("Reproduce(%s) = %v, %v; want an error", file, ok, err)
		}
	}
}

func TestScanSortsFindingsByFileThenLine(t *testing.T) {
	line := "k = " + quoted(fakeAWSKey) + "\n"
	root := writeTree(t, map[string]string{
		"b.txt":   line,
		"a/z.txt": line,
		"a.txt":   "x\n" + line + line + fakeGitHub + " " + fakeAWSKey + "\n",
	})
	want := []string{"a.txt:2", "a.txt:3", "a.txt:4", "a.txt:4", "a/z.txt:1", "b.txt:1"}

	first, second := mustScan(t, root), mustScan(t, root)

	if !slices.Equal(targets(first), want) {
		t.Fatalf("targets = %v, want %v", targets(first), want)
	}
	if !slices.Equal(ruleIDs(first)[2:4], []string{"aws-access-key-id", "github-token"}) {
		t.Fatalf("rules on one line = %v", ruleIDs(first)[2:4])
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("two scans of the same tree differ")
	}
}

func TestScanFailsWhenTheTreeHasTooManyFiles(t *testing.T) {
	root := writeTree(t, map[string]string{"a.txt": "a\n", "b.txt": "b\n", "c.txt": "c\n"})

	atLimit, errAtLimit := scanTree(root, 3)
	_, errOver := scanTree(root, 2)

	if errAtLimit != nil || len(atLimit) != 0 {
		t.Fatalf("at the limit: findings = %d, err = %v", len(atLimit), errAtLimit)
	}
	if errOver == nil || !strings.Contains(errOver.Error(), "more than 2 files") {
		t.Fatalf("over the limit: err = %v", errOver)
	}
}

func TestScanFailsWhenTheRootCannotBeOpened(t *testing.T) {
	findings, err := Scan(filepath.Join(t.TempDir(), "missing"))

	if err == nil || findings != nil {
		t.Fatalf("findings = %v, err = %v; want an error", findings, err)
	}
}

func TestScanFailsOnUnreadableDirectoriesAndFiles(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read everything")
	}
	cases := []struct {
		name string
		path string
		mode os.FileMode
	}{
		{"directory", "locked", 0o000},
		{"file", "locked/creds.txt", 0o000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"locked/creds.txt": "k = " + quoted(fakeAWSKey) + "\n"})
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o755) })

			findings, err := Scan(root)

			if err == nil {
				t.Fatalf("findings = %v; want an error, not a silently partial scan", targets(findings))
			}
		})
	}
}

func TestReproduce(t *testing.T) {
	line := "k = " + quoted(fakeAWSKey) + "\n"
	root := writeTree(t, map[string]string{
		"live.txt":   "x\n" + line,
		"fixed.txt":  "x\nk = os.environ['AWS_KEY']\n",
		"binary.dat": line + "\x00",
		"huge.txt":   line + strings.Repeat("a", maxFileBytes),
	})
	at := func(file string, lineNo int) *finding.Location { return &finding.Location{File: file, Line: lineNo} }
	cases := []struct {
		name    string
		root    string
		rule    string
		loc     *finding.Location
		want    bool
		wantErr bool
	}{
		{"the secret is still there", root, "aws-access-key-id", at("live.txt", 2), true, false},
		{"the secret was removed", root, "aws-access-key-id", at("fixed.txt", 2), false, false},
		{"another line", root, "aws-access-key-id", at("live.txt", 1), false, false},
		{"another rule", root, "github-token", at("live.txt", 2), false, false},
		{"no location", root, "aws-access-key-id", nil, false, true},
		{"empty path", root, "aws-access-key-id", at("", 2), false, true},
		{"path that climbs out", root, "aws-access-key-id", at("../live.txt", 2), false, true},
		{"absolute path", root, "aws-access-key-id", at(filepath.Join(root, "live.txt"), 2), false, true},
		{"missing file", root, "aws-access-key-id", at("gone.txt", 2), false, true},
		{"missing root", filepath.Join(root, "missing"), "aws-access-key-id", at("live.txt", 2), false, true},
		{"file is now binary", root, "aws-access-key-id", at("binary.dat", 1), false, true},
		{"file is now too large", root, "aws-access-key-id", at("huge.txt", 1), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := finding.Finding{Source: Source, RuleID: tc.rule, Location: tc.loc}

			got, err := Reproduce(tc.root, f)

			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("Reproduce = %v, %v; want %v, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestReproduceConfirmsEveryFindingScanReturns(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.txt":     "k = " + quoted(fakeAWSKey) + "\n" + passwordAssign + "\n",
		"keys/id.k": fakePEM + "\n",
	})

	findings := mustScan(t, root)

	if len(findings) != 3 {
		t.Fatalf("findings = %v", targets(findings))
	}
	for _, f := range findings {
		if ok, err := Reproduce(root, f); !ok || err != nil {
			t.Errorf("Reproduce(%s) = %v, %v", f.Target, ok, err)
		}
	}
}
