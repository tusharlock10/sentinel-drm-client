# Phase 3 — Hardware Fingerprint and OS Keystore

**Status**: Done ✓
**Depends on**: Phase 1
**Completed**: 2026-02-28

---

## Goals

- Collect hardware fingerprint components (CPU serial, disk serial, machine ID) on
  Linux, macOS, and Windows.
- Compute `SHA256Hex(cpuSerial + diskSerial + machineID)` as the fingerprint.
- Export `GetMachineID()` for vault key derivation in Phase 7.
- Provide a cross-platform file-based keystore using AES-256-GCM encryption.
  No external keystore dependency — all stdlib crypto.

---

## New Dependencies

None. All functionality uses Go stdlib only.

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/hardware/hardware.go` | Created — `CollectFingerprint()` + `GetMachineID()` + SHA-256 computation |
| `internal/hardware/hardware_linux.go` | Created — Linux-specific component collection |
| `internal/hardware/hardware_darwin.go` | Created — macOS-specific component collection |
| `internal/hardware/hardware_windows.go` | Created — Windows-specific component collection (PowerShell) |
| `internal/keystore/keystore.go` | Created — file-based AES-256-GCM keystore |

---

## Hardware Fingerprint — `internal/hardware/`

### Public API

```go
// hardware.go

// CollectFingerprint gathers hardware identifiers and returns
// SHA256Hex(cpuSerial + diskSerial + machineID).
func CollectFingerprint() (string, error)

// GetMachineID returns the platform-specific stable machine identifier.
// It is the same value used as one of the three inputs to CollectFingerprint.
// Used by Phase 7 to derive the keystore vault key.
func GetMachineID() (string, error)
```

### Internal Interface

Each platform file implements these unexported functions:

```go
func getCPUSerial() (string, error)
func getDiskSerial() (string, error)
func getMachineID() (string, error)
```

### `CollectFingerprint` Implementation

```go
func CollectFingerprint() (string, error) {
    cpu, err := getCPUSerial()
    if err != nil {
        return "", fmt.Errorf("collect CPU serial: %w", err)
    }
    disk, err := getDiskSerial()
    if err != nil {
        return "", fmt.Errorf("collect disk serial: %w", err)
    }
    mid, err := getMachineID()
    if err != nil {
        return "", fmt.Errorf("collect machine ID: %w", err)
    }

    sum := sha256.Sum256([]byte(cpu + disk + mid))
    return hex.EncodeToString(sum[:]), nil
}
```

**No fallbacks.** If any component cannot be read, return an error immediately.
The customer must have a machine where all three components are accessible.

---

### Linux — `hardware_linux.go`

Build tag: `//go:build linux`

#### `getCPUSerial()`

1. Try reading `/sys/class/dmi/id/product_uuid` (x86, most VMs).
2. If not available, parse `/proc/cpuinfo` for the `Serial` field (ARM/embedded).
3. If neither available, return error.

#### `getDiskSerial()`

1. Find the root device via `findmnt -n -o SOURCE /`.
2. Extract base device name (strip partition number and trailing `p` for NVMe).
3. Read `/sys/block/<device>/serial`.

#### `getMachineID()`

Read `/etc/machine-id` (systemd persistent identifier, present on all modern Linux).

---

### macOS — `hardware_darwin.go`

Build tag: `//go:build darwin`

#### `getCPUSerial()`

Parse `IOPlatformSerialNumber` from `ioreg -rd1 -c IOPlatformExpertDevice` output.

#### `getDiskSerial()`

Parse `Volume UUID` or `Disk / Partition UUID` from `diskutil info /` output.

#### `getMachineID()`

Parse `IOPlatformUUID` from `ioreg -rd1 -c IOPlatformExpertDevice` output.

---

### Windows — `hardware_windows.go`

Build tag: `//go:build windows`

All Windows implementations use PowerShell (`powershell.exe`) via:

```go
func psQuery(command string) (string, error) {
    out, err := exec.Command(
        "powershell", "-NoProfile", "-NonInteractive", "-Command", command,
    ).Output()
    ...
}
```

`wmic` is deprecated/removed on Windows 11. PowerShell `Get-CimInstance` is the
correct replacement and is available on all supported Windows versions.

#### `getCPUSerial()`

```powershell
(Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1).ProcessorId
```

#### `getDiskSerial()`

```powershell
(Get-CimInstance -ClassName Win32_DiskDrive -Filter 'Index=0' | Select-Object -First 1).SerialNumber
```

#### `getMachineID()`

```powershell
(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
```

---

## Keystore — `internal/keystore/keystore.go`

### Design

The keystore is a single encrypted file on disk. Each entry is independently
encrypted with AES-256-GCM. The encryption key (vault key) is derived externally
by the Phase 7 orchestrator using `DeriveVaultKey(machineID)` and passed in at
construction time. This keeps the keystore package dependency-free and testable
in isolation.

### File Format

The keystore file is a JSON object where each value is `base64(nonce[12] || ciphertext)`:

```json
{
  "machine-private-key": "<base64(nonce + ciphertext)>",
  "state-encryption-key": "<base64(nonce + ciphertext)>"
}
```

Writes are atomic: write to `<path>.tmp`, then `os.Rename` to `<path>`.
File permissions: `0600`. Directory permissions: `0700`.

### File Location

| OS | Path |
|---|---|
| Linux | `$XDG_DATA_HOME/sentinel-drm/keystore.enc` (default `~/.local/share/sentinel-drm/keystore.enc`) |
| macOS | `~/Library/Application Support/sentinel-drm/keystore.enc` |
| Windows | `%APPDATA%\sentinel-drm\keystore.enc` |

### Interface and Public API

```go
var ErrNotFound = errors.New("key not found")

const (
    KeyMachinePrivateKey  = "machine-private-key"
    KeyStateEncryptionKey = "state-encryption-key"
)

type Keystore interface {
    Store(key string, data []byte) error
    Retrieve(key string) ([]byte, error)
    Delete(key string) error
}

// New opens an existing keystore file or creates a new one.
// filePath is the path to the encrypted keystore file.
// vaultKey is the 32-byte AES-256-GCM key for all entries.
func New(filePath string, vaultKey [32]byte) (Keystore, error)

// DefaultFilePath returns the platform-specific path for the keystore file.
func DefaultFilePath() (string, error)

// DeriveVaultKey derives a 32-byte AES key from a stable machine identifier.
// Called by the Phase 7 orchestrator using hardware.GetMachineID().
func DeriveVaultKey(machineID string) [32]byte
```

### Implementation Notes

- `New`: reads and parses the file if it exists; starts with an empty map if not.
  Returns an error if the file exists but cannot be parsed.
- `Store`: AES-256-GCM encrypt with a fresh random nonce, update in-memory map,
  flush to disk atomically.
- `Retrieve`: look up in-memory map (returns `ErrNotFound` if absent), decode and
  decrypt.
- `Delete`: remove from map, flush to disk. No-op if key does not exist.
- `DeriveVaultKey`: `SHA256("sentinel-drm-keystore:" + machineID)` — ties the
  keystore file cryptographically to the machine without any additional secret.
  An attacker who copies the file to a different machine cannot decrypt it.

---

## Done Criteria

- [x] `CollectFingerprint()` returns a consistent SHA-256 hex string on the same machine
- [x] `GetMachineID()` returns a non-empty stable identifier
- [x] Each component function (`getCPUSerial`, `getDiskSerial`, `getMachineID`) returns
  non-empty values
- [x] Missing hardware components produce clear error messages (no silent fallbacks)
- [x] `DeriveVaultKey` is deterministic for the same input
- [x] `DefaultFilePath` returns a non-empty platform-specific path
- [x] Keystore `Store` / `Retrieve` roundtrip works for binary data
- [x] Keystore `Retrieve` returns `ErrNotFound` for non-existent keys
- [x] Keystore `Delete` removes stored data
- [x] Keystore file is written with `0600` permissions
- [x] Keystore handles first run (no file) without error
- [x] Keystore returns error on corrupt/unparseable file
