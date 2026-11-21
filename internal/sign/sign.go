// Package sign makes detached signatures over reports, so a reader can check
// that a report was produced by the holder of a key and was not altered.
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// Algorithm is the only signature algorithm this package produces or
	// accepts.
	Algorithm = "ed25519"

	// signingContext opens the signed bytes. It ties a signature to this
	// purpose and format version, so one made here cannot be presented as a
	// signature over something else made with the same key.
	signingContext = "vajra-report-v1\n"
)

// Verify wraps one of these, so a caller can tell which check failed.
var (
	// ErrAlgorithm means the signature names an algorithm other than Ed25519.
	ErrAlgorithm = errors.New("sign: unsupported signature algorithm")
	// ErrKeyID means the signature was made with a different key.
	ErrKeyID = errors.New("sign: signature was made with a different key")
	// ErrDigest means the document is not the one that was signed.
	ErrDigest = errors.New("sign: document does not match the signed digest")
	// ErrSignature means the signature value does not verify: it is damaged,
	// or the digest or timestamp it covers was changed.
	ErrSignature = errors.New("sign: signature is not valid")
)

// Signature is a detached signature over a document.
type Signature struct {
	// Algorithm is always "ed25519".
	Algorithm string `json:"algorithm"`
	// KeyID is the first 16 hex characters of the SHA-256 of the raw public
	// key. It only helps a reader pick the right key; trust comes from Value.
	KeyID string `json:"key_id"`
	// SHA256 is the hex digest of the document.
	SHA256 string `json:"sha256"`
	// SignedAt is covered by the signature, to the second, in UTC.
	SignedAt time.Time `json:"signed_at"`
	// Value is the signature in standard base64.
	Value string `json:"value"`
}

// Sign signs document with the key at privatePath. It refuses a key file
// that group or others can access, because such a key may already be copied.
func Sign(document []byte, privatePath string, now time.Time) (Signature, error) {
	key, err := loadPrivateKey(privatePath)
	if err != nil {
		return Signature{}, err
	}
	// The public half of an Ed25519 private key always has this type.
	public, _ := key.Public().(ed25519.PublicKey)
	// The signed bytes carry the time to the second, so the stored value is
	// cut to the same precision: what is recorded is exactly what is covered.
	signedAt := now.UTC().Truncate(time.Second)
	digest := digestOf(document)
	return Signature{
		Algorithm: Algorithm,
		KeyID:     keyID(public),
		SHA256:    digest,
		SignedAt:  signedAt,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(key, signedBytes(digest, signedAt))),
	}, nil
}

// Verify checks sig against document with the public key at publicPath. The
// error says which check failed: wrong algorithm (ErrAlgorithm), key ID
// mismatch (ErrKeyID), digest mismatch, meaning the document changed
// (ErrDigest), or bad signature (ErrSignature).
func Verify(document []byte, sig Signature, publicPath string) error {
	if sig.Algorithm != Algorithm {
		return fmt.Errorf("%w: %q", ErrAlgorithm, sig.Algorithm)
	}
	public, err := loadPublicKey(publicPath)
	if err != nil {
		return err
	}
	if want := keyID(public); sig.KeyID != want {
		return fmt.Errorf("%w: signature names key %q, this key is %q", ErrKeyID, sig.KeyID, want)
	}
	digest := digestOf(document)
	if sig.SHA256 != digest {
		return fmt.Errorf("%w: the document was changed after signing", ErrDigest)
	}
	// A sub-second part would not be covered by the signature, so it could be
	// altered freely. Sign never produces one.
	if !sig.SignedAt.Equal(sig.SignedAt.Truncate(time.Second)) {
		return fmt.Errorf("%w: timestamp is not in whole seconds", ErrSignature)
	}
	value, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("%w: value is not base64", ErrSignature)
	}
	if !ed25519.Verify(public, signedBytes(digest, sig.SignedAt), value) {
		return fmt.Errorf("%w: the signature or its timestamp was changed", ErrSignature)
	}
	return nil
}

// Marshal encodes the signature as indented JSON with a trailing newline.
func (s Signature) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sign: encode signature: %w", err)
	}
	return append(raw, '\n'), nil
}

// ParseSignature decodes a signature file. Unknown fields and trailing data
// are errors: a signature that says more than this package understands is
// not one it can vouch for.
func ParseSignature(raw []byte) (Signature, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var sig Signature
	if err := dec.Decode(&sig); err != nil {
		return Signature{}, fmt.Errorf("sign: decode signature: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Signature{}, errors.New("sign: decode signature: unexpected data after the signature")
	}
	return sig, nil
}

func digestOf(document []byte) string {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])
}

// signedBytes is what the key actually signs: the context line, the document
// digest and the signing time. Covering the time means it cannot be edited
// to back-date or post-date a report.
func signedBytes(digest string, signedAt time.Time) []byte {
	return []byte(signingContext + digest + "\n" + signedAt.UTC().Format(time.RFC3339))
}
