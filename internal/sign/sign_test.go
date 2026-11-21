package sign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var signedAt = time.Date(2026, 11, 21, 19, 54, 40, 0, time.UTC)

var document = []byte(`{"tool":"vajra","findings":[]}` + "\n")

type keyPair struct {
	private string
	public  string
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	dir := t.TempDir()
	pair := keyPair{private: filepath.Join(dir, "report.key"), public: filepath.Join(dir, "report.pub")}
	if err := GenerateKey(pair.private, pair.public); err != nil {
		t.Fatal(err)
	}
	return pair
}

func mustSign(t *testing.T, pair keyPair) Signature {
	t.Helper()
	sig, err := Sign(document, pair.private, signedAt)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func writeFile(t *testing.T, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to the umask; the tests need the exact mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func pemBytes(pemType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
}

func ecdsaPEMs(t *testing.T) (private, public []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes(privatePEMType, privateDER), pemBytes(publicPEMType, publicDER)
}

func TestGenerateKeyWritesPEMFilesWithTheDocumentedModes(t *testing.T) {
	pair := newKeyPair(t)

	for _, want := range []struct {
		path    string
		mode    os.FileMode
		pemType string
	}{
		{pair.private, 0o600, "PRIVATE KEY"},
		{pair.public, 0o644, "PUBLIC KEY"},
	} {
		info, err := os.Stat(want.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want.mode {
			t.Errorf("%s: mode = %v; want %04o", want.path, info.Mode().Perm(), want.mode)
		}
		raw, err := os.ReadFile(want.path)
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != want.pemType || len(rest) != 0 {
			t.Errorf("%s: not a single %q PEM block", want.path, want.pemType)
		}
	}
}

func TestGenerateKeyNeverOverwritesAnExistingFile(t *testing.T) {
	tests := []struct {
		name string
		// existing picks which half of the pair is already on disk.
		existing func(keyPair) string
	}{
		{"existing private key", func(p keyPair) string { return p.private }},
		{"existing public key", func(p keyPair) string { return p.public }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pair := keyPair{private: filepath.Join(dir, "k.key"), public: filepath.Join(dir, "k.pub")}
			existing := tc.existing(pair)
			if err := os.WriteFile(existing, []byte("precious"), 0o600); err != nil {
				t.Fatal(err)
			}

			err := GenerateKey(pair.private, pair.public)

			if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("err = %v; want a file-exists error", err)
			}
			if got, _ := os.ReadFile(existing); string(got) != "precious" {
				t.Fatalf("existing file was overwritten: %q", got)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatalf("a half-made key pair was left behind: %v", entries)
			}
		})
	}
}

func TestSignThenVerifyRoundTripsThroughJSON(t *testing.T) {
	pair := newKeyPair(t)

	sig, err := Sign(document, pair.private, signedAt.Add(300*time.Millisecond).In(time.FixedZone("ist", 19800)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignature(raw)
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(document, parsed, pair.public); err != nil {
		t.Fatalf("Verify after a JSON round trip: %v", err)
	}
	if sig.Algorithm != "ed25519" || len(sig.KeyID) != 16 || len(sig.SHA256) != 64 {
		t.Errorf("signature fields = %+v", sig)
	}
	if !sig.SignedAt.Equal(signedAt) || sig.SignedAt.Location() != time.UTC {
		t.Errorf("SignedAt = %v; want %v in UTC, cut to the second", sig.SignedAt, signedAt)
	}
	if !strings.HasSuffix(string(raw), "}\n") || !strings.Contains(string(raw), "\n  \"key_id\": ") {
		t.Errorf("Marshal output is not indented JSON with a trailing newline:\n%s", raw)
	}
}

func TestVerifyRejectsAnySingleByteChangeToTheDocument(t *testing.T) {
	pair := newKeyPair(t)
	sig := mustSign(t, pair)

	for i := range document {
		altered := append([]byte(nil), document...)
		altered[i] ^= 0x01

		if err := Verify(altered, sig, pair.public); !errors.Is(err, ErrDigest) {
			t.Fatalf("byte %d flipped: err = %v; want ErrDigest", i, err)
		}
	}
	if err := Verify(append(append([]byte(nil), document...), ' '), sig, pair.public); !errors.Is(err, ErrDigest) {
		t.Fatalf("byte appended: err = %v; want ErrDigest", err)
	}
}

func TestVerifyNamesTheCheckThatFailed(t *testing.T) {
	pair := newKeyPair(t)
	other := newKeyPair(t)
	good := mustSign(t, pair)
	tests := []struct {
		name   string
		public string
		alter  func(Signature) Signature
		want   error
	}{
		{"timestamp moved by a second", pair.public, func(s Signature) Signature {
			s.SignedAt = s.SignedAt.Add(time.Second)
			return s
		}, ErrSignature},
		{"timestamp moved by a nanosecond", pair.public, func(s Signature) Signature {
			s.SignedAt = s.SignedAt.Add(time.Nanosecond)
			return s
		}, ErrSignature},
		{"signature from another key", other.public, func(s Signature) Signature { return s }, ErrKeyID},
		{"another key with the key ID forged to match", other.public, func(s Signature) Signature {
			s.KeyID = mustSign(t, other).KeyID
			return s
		}, ErrSignature},
		{"wrong algorithm", pair.public, func(s Signature) Signature {
			s.Algorithm = "rsa-sha256"
			return s
		}, ErrAlgorithm},
		{"empty algorithm", pair.public, func(s Signature) Signature {
			s.Algorithm = ""
			return s
		}, ErrAlgorithm},
		{"digest replaced", pair.public, func(s Signature) Signature {
			s.SHA256 = strings.Repeat("0", 64)
			return s
		}, ErrDigest},
		{"value is not base64", pair.public, func(s Signature) Signature {
			s.Value = "!!not base64!!"
			return s
		}, ErrSignature},
		{"value is too short", pair.public, func(s Signature) Signature {
			s.Value = base64.StdEncoding.EncodeToString([]byte("short"))
			return s
		}, ErrSignature},
		{"value has one bit flipped", pair.public, func(s Signature) Signature {
			value, _ := base64.StdEncoding.DecodeString(s.Value)
			value[0] ^= 0x01
			s.Value = base64.StdEncoding.EncodeToString(value)
			return s
		}, ErrSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig := tc.alter(good)

			err := Verify(document, sig, tc.public)

			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}
}

func TestSignatureCoversThePurposeLine(t *testing.T) {
	// A signature over the bare digest, made with the right key, must not
	// verify: only the full context-prefixed bytes count.
	pair := newKeyPair(t)
	key, err := loadPrivateKey(pair.private)
	if err != nil {
		t.Fatal(err)
	}
	sig := mustSign(t, pair)
	sig.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(sig.SHA256)))

	if err := Verify(document, sig, pair.public); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v; want ErrSignature", err)
	}
	want := "vajra-report-v1\n" + sig.SHA256 + "\n2026-11-21T19:54:40Z"
	if got := string(signedBytes(sig.SHA256, signedAt)); got != want {
		t.Fatalf("signed bytes = %q; want %q", got, want)
	}
}

func TestSignRefusesAPrivateKeyOthersCanAccess(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o601} {
		pair := newKeyPair(t)
		if err := os.Chmod(pair.private, mode); err != nil {
			t.Fatal(err)
		}

		_, err := Sign(document, pair.private, signedAt)

		if err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("mode %04o: err = %v; want a refusal that names the mode", mode, err)
		}
	}
}

func TestSignAcceptsAnOwnerOnlyKey(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		pair := newKeyPair(t)
		if err := os.Chmod(pair.private, mode); err != nil {
			t.Fatal(err)
		}

		if _, err := Sign(document, pair.private, signedAt); err != nil {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
}

func TestSignRejectsUnusablePrivateKeyFiles(t *testing.T) {
	ecdsaPrivate, _ := ecdsaPEMs(t)
	pair := newKeyPair(t)
	publicPEM, err := os.ReadFile(pair.public)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{"not PEM at all", []byte("this is not a key"), "no PEM block"},
		{"empty file", nil, "no PEM block"},
		{"a public key where the private key should be", publicPEM, `want "PRIVATE KEY"`},
		{"PEM whose contents are not PKCS#8", pemBytes(privatePEMType, []byte("garbage")), "not valid PKCS#8"},
		{"a key of another type", ecdsaPrivate, "not an Ed25519 key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFile(t, "bad.key", tc.content, 0o600)

			_, err := Sign(document, path, signedAt)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestSignReportsAMissingPrivateKey(t *testing.T) {
	_, err := Sign(document, filepath.Join(t.TempDir(), "absent.key"), signedAt)

	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v; want a not-exist error", err)
	}
}

func TestVerifyRejectsUnusablePublicKeyFiles(t *testing.T) {
	_, ecdsaPublic := ecdsaPEMs(t)
	pair := newKeyPair(t)
	sig := mustSign(t, pair)
	privatePEM, err := os.ReadFile(pair.private)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{"not PEM at all", []byte("ssh-ed25519 AAAA"), "no PEM block"},
		{"a private key where the public key should be", privatePEM, `want "PUBLIC KEY"`},
		{"PEM whose contents are not PKIX", pemBytes(publicPEMType, []byte("garbage")), "not valid PKIX"},
		{"a key of another type", ecdsaPublic, "not an Ed25519 key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFile(t, "bad.pub", tc.content, 0o644)

			err := Verify(document, sig, path)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestVerifyReportsAMissingPublicKey(t *testing.T) {
	pair := newKeyPair(t)
	sig := mustSign(t, pair)

	err := Verify(document, sig, filepath.Join(t.TempDir(), "absent.pub"))

	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v; want a not-exist error", err)
	}
}

func TestParseSignatureRejectsWhatItDoesNotUnderstand(t *testing.T) {
	raw, err := mustSign(t, newKeyPair(t)).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	valid := strings.TrimSpace(string(raw))
	tests := []struct {
		name string
		raw  string
	}{
		{"unknown field", strings.Replace(valid, "{", `{"comment": "trust me",`, 1)},
		{"trailing data", valid + ` {"algorithm": "none"}`},
		{"not JSON", "-----BEGIN SIGNATURE-----"},
		{"empty input", ""},
		{"wrong type for a field", `{"algorithm": 7}`},
		{"timestamp that is not a time", `{"signed_at": "yesterday"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if sig, err := ParseSignature([]byte(tc.raw)); err == nil {
				t.Fatalf("accepted %q as %+v", tc.raw, sig)
			}
		})
	}
}

func TestKeyIDIsStablePerKeyAndDiffersBetweenKeys(t *testing.T) {
	pair, other := newKeyPair(t), newKeyPair(t)

	first, second, foreign := mustSign(t, pair), mustSign(t, pair), mustSign(t, other)

	if first.KeyID != second.KeyID {
		t.Errorf("same key gave IDs %q and %q", first.KeyID, second.KeyID)
	}
	if first.KeyID == foreign.KeyID {
		t.Errorf("two keys share the ID %q", first.KeyID)
	}
}

func TestADirectoryIsNotAKeyFile(t *testing.T) {
	pair := newKeyPair(t)
	sig := mustSign(t, pair)
	dir := filepath.Join(t.TempDir(), "keys")
	// Owner-only, so the permission check passes and the read is reached.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	_, signErr := Sign(document, dir, signedAt)
	verifyErr := Verify(document, sig, dir)

	if signErr == nil || !strings.Contains(signErr.Error(), "read") {
		t.Errorf("Sign with a directory: err = %v; want a read error", signErr)
	}
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "read") {
		t.Errorf("Verify with a directory: err = %v; want a read error", verifyErr)
	}
}

func TestMarshalReportsATimestampJSONCannotCarry(t *testing.T) {
	sig := Signature{Algorithm: Algorithm, SignedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}

	if raw, err := sig.Marshal(); err == nil {
		t.Fatalf("Marshal accepted a five-digit year: %s", raw)
	}
}
