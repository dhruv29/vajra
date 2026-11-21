package redact

import (
	"strings"
	"testing"
)

func TestHeadersRemovesCredentialValuesAndKeepsTheRest(t *testing.T) {
	message := "GET /orders HTTP/1.1\r\nHost: app.test\r\nauthorization: Bearer abc.def\r\nCookie: session=s3cr3t; theme=dark\r\n" +
		"X-Tenant-Token: tenant-secret\r\nAccept: */*\r\n\r\nAuthorization: this line is body text at line start"

	got := Headers(message, "X-Tenant-Token", " ")

	for _, secret := range []string{"abc.def", "s3cr3t", "tenant-secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("%q survived: %s", secret, got)
		}
	}
	for _, kept := range []string{"GET /orders HTTP/1.1\r\n", "Host: app.test\r\n", "Accept: */*\r\n", "authorization: [redacted]\r\n", "Cookie: [redacted]\r\n", "X-Tenant-Token: [redacted]\r\n"} {
		if !strings.Contains(got, kept) {
			t.Errorf("missing %q in %q", kept, got)
		}
	}
}

func TestHeadersHandlesPlainNewlinesResponsesAndEmptyInput(t *testing.T) {
	response := "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; HttpOnly\nset-cookie: other=def\nContent-Type: text/html\n\n<p>Cookie: not a header</p>"

	got := Headers(response)

	if strings.Contains(got, "sid=abc") || strings.Contains(got, "other=def") {
		t.Fatalf("a cookie survived: %q", got)
	}
	if !strings.Contains(got, "Content-Type: text/html\n") || !strings.Contains(got, "<p>Cookie: not a header</p>") {
		t.Fatalf("non-secret content was changed: %q", got)
	}
	if Headers("") != "" {
		t.Fatal("empty input changed")
	}
	if got := Headers("X-A.B: v\nXXAYB: keep", "X-A.B"); !strings.Contains(got, "X-A.B: [redacted]") || !strings.Contains(got, "XXAYB: keep") {
		t.Fatalf("a header name was treated as a pattern: %q", got)
	}
}

func TestValuesScrubsACredentialWhereverATargetEchoesIt(t *testing.T) {
	secret := "Bearer lab-user-token-9f2c"
	text := "HTTP 200\n\n{\n  \"headers\": {\n    \"Authorization\": \"Bearer lab-user-token-9f2c\"\n  },\n" +
		"  \"url\": \"/cb?token=lab-user-token-9f2c\"\n}\nBearer of good news"

	got := Values(text, secret, "session=abc12345xyz; theme=dark", "short")

	if strings.Contains(got, "lab-user-token-9f2c") {
		t.Fatalf("the token survived: %s", got)
	}
	if !strings.Contains(got, "Bearer of good news") || !strings.Contains(got, "token=[redacted]") {
		t.Fatalf("ordinary text was damaged or a bare token was missed: %s", got)
	}
	if got := Values("cookie abc12345xyz sent", "session=abc12345xyz; theme=dark"); strings.Contains(got, "abc12345xyz") {
		t.Fatalf("a cookie value was not scrubbed on its own: %s", got)
	}
	if got := Values("the word short stays", "short"); got != "the word short stays" {
		t.Fatalf("a fragment below the minimum length was scrubbed: %s", got)
	}
	if Values("", secret) != "" || Values("nothing here") != "nothing here" {
		t.Fatal("empty input or no secrets changed the text")
	}
}
