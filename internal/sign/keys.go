package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	privateKeyMode = 0o600
	publicKeyMode  = 0o644
	// othersMask selects the permission bits of group and others. A private
	// key with any of them set can be read or replaced by another account.
	othersMask = 0o077

	privatePEMType = "PRIVATE KEY"
	publicPEMType  = "PUBLIC KEY"

	// maxKeyFileBytes bounds how much of a key file is read. An Ed25519 key
	// in PEM is well under 1 KiB.
	maxKeyFileBytes = 16 << 10
	keyIDHexChars   = 16
)

// GenerateKey creates an Ed25519 key pair and writes privatePath (PEM
// "PRIVATE KEY", PKCS#8, mode 0600) and publicPath (PEM "PUBLIC KEY", PKIX,
// mode 0644). Both files are created exclusively, so an existing key is never
// overwritten: losing a private key makes every report it signed
// unverifiable by anyone who trusted only that key.
func GenerateKey(privatePath, publicPath string) error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("sign: generate key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return fmt.Errorf("sign: encode private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return fmt.Errorf("sign: encode public key: %w", err)
	}
	if err := writeNew(privatePath, privatePEMType, privateDER, privateKeyMode); err != nil {
		return err
	}
	if err := writeNew(publicPath, publicPEMType, publicDER, publicKeyMode); err != nil {
		// Without its public half the new private key is useless, and leaving
		// it behind would make a retry fail. This call created it, so removing
		// it destroys nothing that existed before.
		os.Remove(privatePath)
		return err
	}
	return nil
}

// writeNew creates path, failing if it exists, and writes one PEM block.
func writeNew(path, pemType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("sign: create key file: %w", err)
	}
	// The umask can only have removed bits; set the documented mode exactly.
	err = errors.Join(f.Chmod(mode), pem.Encode(f, &pem.Block{Type: pemType, Bytes: der}), f.Close())
	if err != nil {
		// A partly written key file would block the next attempt.
		os.Remove(path)
		return fmt.Errorf("sign: write key file: %w", err)
	}
	return nil
}

// loadPrivateKey reads the signing key. The mode is checked on the open file,
// not on the path, so the file that was checked is the file that is read.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sign: open private key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("sign: inspect private key: %w", err)
	}
	if perm := info.Mode().Perm(); perm&othersMask != 0 {
		return nil, fmt.Errorf("sign: private key %s has mode %04o, which lets group or others use it; chmod it to 0600", path, perm)
	}
	der, err := readPEM(f, privatePEMType)
	if err != nil {
		return nil, fmt.Errorf("sign: private key %s: %w", path, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// The parser's message is not wrapped: it describes key material.
		return nil, fmt.Errorf("sign: private key %s is not valid PKCS#8", path)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("sign: private key %s is not an Ed25519 key", path)
	}
	return key, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sign: open public key: %w", err)
	}
	defer f.Close()
	der, err := readPEM(f, publicPEMType)
	if err != nil {
		return nil, fmt.Errorf("sign: public key %s: %w", path, err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("sign: public key %s is not valid PKIX: %w", path, err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("sign: public key %s is not an Ed25519 key", path)
	}
	return key, nil
}

// readPEM returns the contents of the first PEM block, which must have the
// wanted type.
func readPEM(r io.Reader, wantType string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxKeyFileBytes))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("PEM block is %q, want %q", block.Type, wantType)
	}
	return block.Bytes, nil
}

// keyID names a public key without carrying it: the first 16 hex characters
// of the SHA-256 of the raw key.
func keyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])[:keyIDHexChars]
}
