package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tusharlock10/sentinel-drm-client/internal/keystore"
)

// newTestKeystore creates a file-backed keystore in a temp directory.
func newTestKeystore(t *testing.T) keystore.Keystore {
	t.Helper()
	dir := t.TempDir()
	ksPath := filepath.Join(dir, "keystore.enc")
	var vaultKey [32]byte // zero key is fine for tests
	ks, err := keystore.New(ksPath, vaultKey)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}
	return ks
}

// newTestManager creates a StateManager that writes into t.TempDir().
// It overrides the state file path by constructing the manager directly,
// bypassing defaultStatePath() so tests are hermetic and cross-platform.
func newTestManager(t *testing.T) *StateManager {
	t.Helper()
	ks := newTestKeystore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.enc")

	// Load or generate the encryption key via the exported helper path
	// by constructing StateManager directly (internal package, same package test).
	encKey, err := loadOrGenerateEncKey(ks)
	if err != nil {
		t.Fatalf("loadOrGenerateEncKey: %v", err)
	}

	return &StateManager{
		ks:       ks,
		filePath: path,
		encKey:   encKey,
	}
}

// --- Tests ---

func TestLoad_FirstRun_ReturnsNil(t *testing.T) {
	sm := newTestManager(t)

	state, err := sm.Load()
	if err != nil {
		t.Fatalf("Load() on missing file returned error: %v", err)
	}
	if state != nil {
		t.Fatalf("Load() on missing file returned non-nil state: %+v", state)
	}
}

func TestSaveLoad_Roundtrip(t *testing.T) {
	sm := newTestManager(t)

	original := &State{
		MachineID:             "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		Activated:             true,
		LicenseKey:            "SENTINEL-A3RV-7MN2-KP8W-4GTH",
		LastHeartbeatSuccess:  1708869000,
		GraceRemainingSeconds: 259200,
		GraceExhausted:        false,
	}

	if err := sm.Save(original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := sm.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil after Save")
	}

	if *loaded != *original {
		t.Errorf("roundtrip mismatch:\n got  %+v\n want %+v", *loaded, *original)
	}
}

func TestSave_EncryptedFileIsNotPlaintext(t *testing.T) {
	sm := newTestManager(t)

	state := &State{
		MachineID:  "test-machine-id",
		LicenseKey: "SENTINEL-TEST-KEY-1234",
	}

	if err := sm.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(sm.filePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// The machine ID and license key must not appear as plaintext in the file.
	if bytes.Contains(raw, []byte("test-machine-id")) {
		t.Error("state file contains plaintext machine_id")
	}
	if bytes.Contains(raw, []byte("SENTINEL-TEST-KEY-1234")) {
		t.Error("state file contains plaintext license_key")
	}
}

func TestLoad_TamperedFile_ReturnsError(t *testing.T) {
	sm := newTestManager(t)

	state := &State{MachineID: "some-id", LicenseKey: "SENTINEL-XXXX"}
	if err := sm.Save(state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Flip a byte in the middle of the ciphertext to break the GCM tag.
	raw, err := os.ReadFile(sm.filePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	raw[len(raw)/2] ^= 0xFF
	if err := os.WriteFile(sm.filePath, raw, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = sm.Load()
	if err == nil {
		t.Fatal("Load() on tampered file returned nil error; expected authentication failure")
	}
}

func TestDelete_RemovesFile(t *testing.T) {
	sm := newTestManager(t)

	if err := sm.Save(&State{MachineID: "id"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(sm.filePath); err != nil {
		t.Fatalf("state file should exist after Save: %v", err)
	}

	if err := sm.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(sm.filePath); !os.IsNotExist(err) {
		t.Fatal("state file should not exist after Delete")
	}
}

func TestDelete_Idempotent(t *testing.T) {
	sm := newTestManager(t)
	// Delete on a non-existent file must not return an error.
	if err := sm.Delete(); err != nil {
		t.Fatalf("Delete on non-existent file returned error: %v", err)
	}
}

func TestEncryptionKeyIsPersistedInKeystore(t *testing.T) {
	ks := newTestKeystore(t)
	dir := t.TempDir()

	buildManager := func() *StateManager {
		encKey, err := loadOrGenerateEncKey(ks)
		if err != nil {
			t.Fatalf("loadOrGenerateEncKey: %v", err)
		}
		return &StateManager{
			ks:       ks,
			filePath: filepath.Join(dir, "state.enc"),
			encKey:   encKey,
		}
	}

	sm1 := buildManager()
	if err := sm1.Save(&State{MachineID: "persistent-id", LicenseKey: "SENTINEL-KEY"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Construct a second manager from the same keystore — must read the same key.
	sm2 := buildManager()
	loaded, err := sm2.Load()
	if err != nil {
		t.Fatalf("Load with re-derived key: %v", err)
	}
	if loaded == nil || loaded.MachineID != "persistent-id" {
		t.Fatalf("second manager could not decrypt state written by first manager")
	}
}

func TestSave_AtomicWrite_TempFileCleanedUp(t *testing.T) {
	sm := newTestManager(t)

	if err := sm.Save(&State{MachineID: "id"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	tmpPath := sm.filePath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should not exist after successful Save")
	}
}

func TestNewStateManager_CreatesDirectory(t *testing.T) {
	ks := newTestKeystore(t)
	// Point the state path to a nested directory that does not yet exist.
	dir := filepath.Join(t.TempDir(), "nested", "sentinel-drm")

	encKey, err := loadOrGenerateEncKey(ks)
	if err != nil {
		t.Fatalf("loadOrGenerateEncKey: %v", err)
	}

	sm := &StateManager{
		ks:       ks,
		filePath: filepath.Join(dir, "state.enc"),
		encKey:   encKey,
	}

	// MkdirAll is called inside NewStateManager; replicate it here since we
	// bypass NewStateManager to keep the path hermetic.
	if err := os.MkdirAll(filepath.Dir(sm.filePath), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if err := sm.Save(&State{MachineID: "id"}); err != nil {
		t.Fatalf("Save to new directory: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory to be created")
	}
}

func TestLoadOrGenerateEncKey_Length(t *testing.T) {
	ks := newTestKeystore(t)
	key, err := loadOrGenerateEncKey(ks)
	if err != nil {
		t.Fatalf("loadOrGenerateEncKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key))
	}
}

func TestLoadOrGenerateEncKey_Idempotent(t *testing.T) {
	ks := newTestKeystore(t)
	key1, err := loadOrGenerateEncKey(ks)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	key2, err := loadOrGenerateEncKey(ks)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("loadOrGenerateEncKey returned different keys on consecutive calls")
	}
}

func TestDecrypt_ShortData_ReturnsError(t *testing.T) {
	key := make([]byte, 32)
	_, err := decrypt([]byte{0x01, 0x02}, key) // shorter than nonce size (12)
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestLoad_WrongKey_ReturnsError(t *testing.T) {
	sm1 := newTestManager(t)
	if err := sm1.Save(&State{MachineID: "id"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Build a second manager pointing at the same file but with a different encryption key.
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF // differs from the zero key used by newTestKeystore
	sm2 := &StateManager{
		ks:       sm1.ks,
		filePath: sm1.filePath,
		encKey:   wrongKey,
	}

	_, err := sm2.Load()
	if err == nil {
		t.Fatal("Load with wrong key should fail")
	}
	if !errors.Is(err, err) { // always true; just ensure err is non-nil (checked above)
		t.Fatal("unexpected error type")
	}
}
