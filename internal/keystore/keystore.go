package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// ErrNotFound is returned by Retrieve when the requested key does not exist.
var ErrNotFound = errors.New("key not found")

// Well-known key names stored in the keystore.
const (
	KeyMachinePrivateKey  = "machine-private-key"
	KeyStateEncryptionKey = "state-encryption-key"
)

// Keystore provides secure persistent storage for secret key material.
type Keystore interface {
	Store(key string, data []byte) error
	Retrieve(key string) ([]byte, error)
	Delete(key string) error
}

type fileKeystore struct {
	filePath string
	vaultKey [32]byte
	entries  map[string]string // key → base64(nonce || ciphertext)
}

// DeriveVaultKey derives a 32-byte AES key from a stable machine identifier.
// Called by the orchestrator using hardware.GetMachineID() before constructing
// the keystore. Tying the key to the machine means copying the keystore file to
// another machine will not yield decryptable data.
func DeriveVaultKey(machineID string) [32]byte {
	return sha256.Sum256([]byte("sentinel-drm-keystore:" + machineID))
}

// DefaultFilePath returns the platform-specific path for the keystore file.
func DefaultFilePath() (string, error) {
	switch runtime.GOOS {
	case "linux":
		base := os.Getenv("XDG_DATA_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("cannot determine home directory: %w", err)
			}
			base = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(base, "sentinel-drm", "keystore.enc"), nil

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", "sentinel-drm", "keystore.enc"), nil

	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", errors.New("APPDATA environment variable not set")
		}
		return filepath.Join(appdata, "sentinel-drm", "keystore.enc"), nil

	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// New opens an existing keystore file or initialises a new empty one.
// filePath is the path to the encrypted keystore file.
// vaultKey is the 32-byte AES-256-GCM key used to encrypt all entries;
// derive it with DeriveVaultKey(hardware.GetMachineID()).
func New(filePath string, vaultKey [32]byte) (Keystore, error) {
	ks := &fileKeystore{
		filePath: filePath,
		vaultKey: vaultKey,
		entries:  make(map[string]string),
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ks, nil // first run — start with empty keystore
		}
		return nil, fmt.Errorf("read keystore file: %w", err)
	}

	if err := json.Unmarshal(data, &ks.entries); err != nil {
		return nil, fmt.Errorf("parse keystore file: %w", err)
	}

	return ks, nil
}

// Store encrypts data and saves it under key. An existing entry is overwritten.
func (ks *fileKeystore) Store(key string, data []byte) error {
	gcm, err := newGCM(ks.vaultKey)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext to nonce, producing nonce || ciphertext.
	combined := gcm.Seal(nonce, nonce, data, nil)
	ks.entries[key] = base64.StdEncoding.EncodeToString(combined)

	return ks.flush()
}

// Retrieve decrypts and returns the data stored under key.
// Returns ErrNotFound if the key does not exist.
func (ks *fileKeystore) Retrieve(key string) ([]byte, error) {
	encoded, ok := ks.entries[key]
	if !ok {
		return nil, ErrNotFound
	}

	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode keystore entry %q: %w", key, err)
	}

	gcm, err := newGCM(ks.vaultKey)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(combined) < nonceSize {
		return nil, fmt.Errorf("keystore entry %q is too short to contain a nonce", key)
	}

	plaintext, err := gcm.Open(nil, combined[:nonceSize], combined[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt keystore entry %q: %w", key, err)
	}

	return plaintext, nil
}

// Delete removes key from the keystore. No-op if the key does not exist.
func (ks *fileKeystore) Delete(key string) error {
	if _, ok := ks.entries[key]; !ok {
		return nil
	}
	delete(ks.entries, key)
	return ks.flush()
}

// flush writes the in-memory entries to disk atomically.
func (ks *fileKeystore) flush() error {
	if err := os.MkdirAll(filepath.Dir(ks.filePath), 0700); err != nil {
		return fmt.Errorf("create keystore directory: %w", err)
	}

	data, err := json.Marshal(ks.entries)
	if err != nil {
		return fmt.Errorf("marshal keystore: %w", err)
	}

	tmpPath := ks.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write keystore temp file: %w", err)
	}

	if err := os.Rename(tmpPath, ks.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename keystore file: %w", err)
	}

	return nil
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm, nil
}
