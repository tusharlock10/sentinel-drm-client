package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"unicode/utf8"
)

// Base64URLEncode encodes data using base64url without padding.
// Matches Python's: base64.urlsafe_b64encode(data).rstrip(b"=").decode()
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes a base64url string (with or without padding).
func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ParseECPublicKeyPEM parses a PEM-encoded EC P-256 public key.
func ParseECPublicKeyPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an EC public key")
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, errors.New("key is not P-256")
	}
	return ecPub, nil
}

// ParseECPrivateKeyPEM parses a PEM-encoded EC P-256 private key (PKCS8 format).
func ParseECPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an EC private key")
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, errors.New("key is not P-256")
	}
	return ecKey, nil
}

// GenerateECKeyPair generates a new EC P-256 keypair.
func GenerateECKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ECPublicKeyToPEM serializes an EC public key to a PEM string (PKIX/SubjectPublicKeyInfo format).
func ECPublicKeyToPEM(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// ECPrivateKeyToPEM serializes an EC private key to PEM bytes (PKCS8 format).
func ECPrivateKeyToPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block), nil
}

// SignECDSA signs data with ECDSA-SHA256 and returns a DER-encoded signature.
// Matches the output format of Python's cryptography library.
func SignECDSA(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
}

// VerifyECDSA verifies an ECDSA-SHA256 signature. sig must be DER-encoded.
func VerifyECDSA(publicKey *ecdsa.PublicKey, data []byte, sig []byte) error {
	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(publicKey, hash[:], sig) {
		return errors.New("invalid signature")
	}
	return nil
}

// CanonicalJSON serializes v to canonical JSON with sorted keys at all levels.
// Output is byte-identical to Python's:
//
//	json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var obj any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, obj); err != nil {
		return nil, err
	}
	return escapeNonASCII(buf.Bytes()), nil
}

// escapeNonASCII replaces every non-ASCII rune with its \uXXXX (or surrogate pair) form.
// This matches Python's ensure_ascii=True behavior.
// All JSON structural characters are ASCII, so this is safe to apply to the entire output.
func escapeNonASCII(b []byte) []byte {
	hasNonASCII := false
	for _, c := range b {
		if c >= 0x80 {
			hasNonASCII = true
			break
		}
	}
	if !hasNonASCII {
		return b
	}

	var buf bytes.Buffer
	buf.Grow(len(b))
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r < 0x80 {
			buf.WriteByte(b[i])
			i++
			continue
		}
		if r <= 0xFFFF {
			fmt.Fprintf(&buf, `\u%04x`, r)
		} else {
			// Encode as a UTF-16 surrogate pair for runes outside the BMP.
			r -= 0x10000
			high := 0xD800 + (r>>10)&0x3FF
			low := 0xDC00 + r&0x3FF
			fmt.Fprintf(&buf, `\u%04x\u%04x`, high, low)
		}
		i += size
	}
	return buf.Bytes()
}

// writeCanonical recursively writes JSON with alphabetically sorted keys.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		// json.Marshal escapes non-ASCII characters to \uXXXX, matching ensure_ascii=True.
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// SHA256Hex returns the SHA-256 hex digest of data.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SHA256File computes the SHA-256 hex digest of a file without loading it entirely into memory.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
