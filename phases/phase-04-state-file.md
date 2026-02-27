# Phase 4 — Encrypted State File

**Status**: Pending
**Depends on**: Phase 3 (keystore)

---

## Goals

- Persist machine state (machine ID, activation status, grace period tracking) in an
  encrypted local file.
- Encryption key stored in OS keystore (Phase 3).
- Atomic writes to prevent corruption on crash.

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/state/state.go` | Created — state struct, encryption, load/save, file paths |

---

## State File Location

The state file is stored in a platform-appropriate data directory:

| OS | Path |
|---|---|
| Linux | `$XDG_DATA_HOME/sentinel-drm/state.enc` (default: `~/.local/share/sentinel-drm/state.enc`) |
| macOS | `~/Library/Application Support/sentinel-drm/state.enc` |
| Windows | `%APPDATA%\sentinel-drm\state.enc` |

Use `os.UserConfigDir()` or manual path construction per platform. Create the
directory if it doesn't exist (`os.MkdirAll` with `0700` permissions).

---

## State Structure

```go
type State struct {
    MachineID             string `json:"machine_id"`              // UUID v4, generated once at first run
    Activated             bool   `json:"activated"`               // true after successful activation
    LicenseKey            string `json:"license_key"`             // license key from the .lic file
    LastHeartbeatSuccess  int64  `json:"last_heartbeat_success"`  // unix timestamp of last successful heartbeat
    GraceRemainingSeconds int64  `json:"grace_remaining_seconds"` // remaining grace quota in seconds
    GraceExhausted        bool   `json:"grace_exhausted"`         // true once grace has been fully consumed
}
```

**Field semantics:**

- `MachineID`: Generated with `uuid.New()` on first run. Immutable after creation.
  This is the `machine_id` sent to the backend in all DRM requests.

- `Activated`: Set to `true` after a successful `/drm/activate/` call. On subsequent
  runs, the client sends a heartbeat instead of re-activating.

- `LicenseKey`: Stored so the client can detect if the user changed the license file.
  If the license key in the state file doesn't match the license file, the client
  must re-activate (reset `Activated = false`).

- `LastHeartbeatSuccess`: Unix timestamp. Used to calculate how long the client
  has been offline. Updated after each successful heartbeat.

- `GraceRemainingSeconds`: Initialized to `heartbeat_grace_period_days * 86400`.
  Decremented by the heartbeat interval on each missed heartbeat. Never reset —
  successful heartbeats stop consumption but don't restore quota.

- `GraceExhausted`: Set to `true` when `GraceRemainingSeconds` reaches 0. Once true,
  any single missed heartbeat causes immediate shutdown (no more grace).

---

## Encryption

### Key Management

The encryption key is a 32-byte random value stored in the OS keystore (Phase 3)
under the key name `"state-encryption-key"`.

On first run:
1. Try `keystore.Retrieve("state-encryption-key")`.
2. If not found, generate 32 random bytes via `crypto/rand`, store with
   `keystore.Store("state-encryption-key", key)`.

### Encryption Algorithm

AES-256-GCM (same as the backend uses for private key encryption).

**On-disk format:**

```
[nonce: 12 bytes][ciphertext: variable length]
```

No additional associated data (AAD). The file is self-contained.

### Encrypt

```go
func encrypt(plaintext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize()) // 12 bytes
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
    return append(nonce, ciphertext...), nil
}
```

### Decrypt

```go
func decrypt(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}
```

---

## StateManager

```go
type StateManager struct {
    ks       keystore.Keystore
    filePath string
    encKey   []byte
}
```

### `NewStateManager(ks keystore.Keystore) (*StateManager, error)`

1. Determine state file path based on OS.
2. Create parent directory if it doesn't exist.
3. Load or generate encryption key from keystore.
4. Return the `StateManager`.

### `Load() (*State, error)`

1. Check if state file exists (`os.Stat`).
2. If file doesn't exist: return `nil, nil` (first run — caller creates initial state).
3. Read entire file.
4. Decrypt with AES-256-GCM.
5. JSON unmarshal into `State`.
6. Return `&state, nil`.

If decryption fails (tampered file, wrong key): return error. The caller must
handle this — for STANDARD licenses, the client will attempt to re-sync with
the server.

### `Save(state *State) error`

1. JSON marshal the state.
2. Encrypt with AES-256-GCM (new random nonce each time).
3. Write to a temporary file in the same directory (`state.enc.tmp`).
4. `os.Rename` the temp file to the actual path (atomic on POSIX).
5. Return nil.

**Atomic writes prevent corruption**: If the process is killed during write, the
temp file is left behind but the actual state file remains intact. On next startup,
the temp file is ignored (and cleaned up if present).

### `Delete() error`

Remove the state file from disk. Used during decommission cleanup.

---

## First Run Detection

The orchestrator (Phase 7) uses `Load()` to detect first run:

```go
state, err := stateMgr.Load()
if err != nil {
    // Corrupted state file — need server re-sync
}
if state == nil {
    // First run — generate machine ID, create initial state
    state = &State{
        MachineID:             uuid.New().String(),
        Activated:             false,
        LicenseKey:            license.LicenseKey,
        GraceRemainingSeconds: int64(*license.HeartbeatGracePeriodDays) * 86400,
    }
    stateMgr.Save(state)
}
```

---

## License Key Change Detection

If `state.LicenseKey != license.LicenseKey`, the user has switched to a different
license file. The client must:
1. Reset `Activated = false`
2. Update `LicenseKey`
3. Re-initialize grace period from the new license
4. Re-activate with the server

---

## Done Criteria

- [ ] State file is created in the correct platform-specific directory
- [ ] `Save` then `Load` roundtrip produces identical state
- [ ] `Load` returns `nil` (not error) for non-existent file (first run)
- [ ] Encrypted file is not readable as plaintext
- [ ] Tampered file causes `Load` to return an error (GCM authentication fails)
- [ ] Atomic write: killing process during `Save` doesn't corrupt existing state
- [ ] Encryption key is stored in and retrieved from OS keystore
- [ ] Directory is created with `0700` permissions if it doesn't exist
