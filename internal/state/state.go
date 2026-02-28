package state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/tusharlock10/sentinel-drm-client/internal/keystore"
)

// State is the persisted runtime state for a STANDARD license client.
// It is encrypted at rest using AES-256-GCM with a key stored in the OS keystore.
type State struct {
	MachineID             string `json:"machine_id"`              // UUID v4, generated once at first run
	Activated             bool   `json:"activated"`               // true after successful /drm/activate/ call
	LicenseKey            string `json:"license_key"`             // license key from the .lic file
	LastHeartbeatSuccess  int64  `json:"last_heartbeat_success"`  // unix timestamp of last successful heartbeat
	GraceRemainingSeconds int64  `json:"grace_remaining_seconds"` // remaining offline grace quota in seconds
	GraceExhausted        bool   `json:"grace_exhausted"`         // true once grace quota has been fully consumed
}

// StateManager handles loading, saving, and deleting the encrypted state file.
type StateManager struct {
	ks       keystore.Keystore
	filePath string
	encKey   []byte
}

// NewStateManager initialises the StateManager.
// It determines the platform-specific state file path, creates the parent directory,
// and loads or generates the AES-256-GCM encryption key from the keystore.
func NewStateManager(ks keystore.Keystore) (*StateManager, error) {
	path, err := defaultStatePath()
	if err != nil {
		return nil, fmt.Errorf("determine state file path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	encKey, err := loadOrGenerateEncKey(ks)
	if err != nil {
		return nil, err
	}

	return &StateManager{
		ks:       ks,
		filePath: path,
		encKey:   encKey,
	}, nil
}

// Load reads and decrypts the state file.
// Returns nil, nil on first run (file does not exist).
// Returns an error if the file exists but is corrupted or tampered with.
func (sm *StateManager) Load() (*State, error) {
	data, err := os.ReadFile(sm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // first run
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	plaintext, err := decrypt(data, sm.encKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt state file: %w", err)
	}

	var s State
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}

	return &s, nil
}

// Save marshals state, encrypts it with a fresh nonce, and writes it atomically.
func (sm *StateManager) Save(state *State) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	ciphertext, err := encrypt(plaintext, sm.encKey)
	if err != nil {
		return err
	}

	tmpPath := sm.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write state temp file: %w", err)
	}

	if err := os.Rename(tmpPath, sm.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename state file: %w", err)
	}

	return nil
}

// Delete removes the state file from disk. Used during decommission cleanup.
// No-op if the file does not exist.
func (sm *StateManager) Delete() error {
	err := os.Remove(sm.filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete state file: %w", err)
	}
	return nil
}

// defaultStatePath returns the platform-specific state file path.
// The state file lives in the same sentinel-drm directory as the keystore.
func defaultStatePath() (string, error) {
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
		return filepath.Join(base, "sentinel-drm", "state.enc"), nil

	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", "sentinel-drm", "state.enc"), nil

	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", errors.New("APPDATA environment variable not set")
		}
		return filepath.Join(appdata, "sentinel-drm", "state.enc"), nil

	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// loadOrGenerateEncKey retrieves the state encryption key from the keystore,
// generating and storing a new random key if one does not yet exist.
func loadOrGenerateEncKey(ks keystore.Keystore) ([]byte, error) {
	key, err := ks.Retrieve(keystore.KeyStateEncryptionKey)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("state encryption key in keystore has unexpected length %d (want 32)", len(key))
		}
		return key, nil
	}
	if !errors.Is(err, keystore.ErrNotFound) {
		return nil, fmt.Errorf("retrieve state encryption key: %w", err)
	}

	// First run — generate a new 32-byte key.
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate state encryption key: %w", err)
	}
	if err := ks.Store(keystore.KeyStateEncryptionKey, key); err != nil {
		return nil, fmt.Errorf("store state encryption key: %w", err)
	}
	return key, nil
}

// encrypt encrypts plaintext with AES-256-GCM using a fresh random nonce.
// On-disk format: nonce(12 bytes) || ciphertext.
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce, producing nonce || ciphertext.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts AES-256-GCM data produced by encrypt.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return nil, errors.New("decryption failed: authentication tag mismatch")
	}
	return plaintext, nil
}
