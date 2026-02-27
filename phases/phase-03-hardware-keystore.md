# Phase 3 — Hardware Fingerprint and OS Keystore

**Status**: Pending
**Depends on**: Phase 1

---

## Goals

- Collect hardware fingerprint components (CPU serial, disk serial, machine ID) on
  Linux, macOS, and Windows.
- Compute `SHA256Hex(cpuSerial + diskSerial + machineID)` as the fingerprint.
- Provide a cross-platform OS keystore abstraction for secure secret storage.

---

## New Dependencies

```bash
go get github.com/zalando/go-keyring
```

`go-keyring` provides cross-platform keystore access:
- Linux: Secret Service API (D-Bus, GNOME Keyring / KDE Wallet)
- macOS: Keychain
- Windows: Credential Manager

This is a justified dependency — implementing three platform-specific keystore
integrations from scratch is significant effort for no security benefit.

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/hardware/hardware.go` | Created — `CollectFingerprint()` + SHA-256 computation |
| `internal/hardware/hardware_linux.go` | Created — Linux-specific component collection |
| `internal/hardware/hardware_darwin.go` | Created — macOS-specific component collection |
| `internal/hardware/hardware_windows.go` | Created — Windows-specific component collection |
| `internal/keystore/keystore.go` | Created — interface + `go-keyring` backed implementation |

---

## Hardware Fingerprint — `internal/hardware/`

### Public API

```go
// hardware.go

// CollectFingerprint gathers hardware identifiers and returns
// SHA256Hex(cpuSerial + diskSerial + machineID).
func CollectFingerprint() (string, error)
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
    cpuSerial, err := getCPUSerial()
    if err != nil {
        return "", fmt.Errorf("collect CPU serial: %w", err)
    }
    diskSerial, err := getDiskSerial()
    if err != nil {
        return "", fmt.Errorf("collect disk serial: %w", err)
    }
    machineID, err := getMachineID()
    if err != nil {
        return "", fmt.Errorf("collect machine ID: %w", err)
    }

    combined := cpuSerial + diskSerial + machineID
    hash := sha256.Sum256([]byte(combined))
    return hex.EncodeToString(hash[:]), nil
}
```

**No fallbacks.** If any component cannot be read, return an error immediately.
The customer must have a machine where all three components are accessible.

---

### Linux — `hardware_linux.go`

#### `getCPUSerial()`

1. Try reading `/sys/class/dmi/id/product_uuid` (requires root or `dmidecode` access).
2. If not available, parse `/proc/cpuinfo` for the `Serial` field (ARM/embedded).
3. If neither available, return error.

```go
func getCPUSerial() (string, error) {
    // Primary: DMI product UUID
    data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
    if err == nil {
        val := strings.TrimSpace(string(data))
        if val != "" {
            return val, nil
        }
    }
    // Fallback: /proc/cpuinfo Serial (ARM)
    data, err = os.ReadFile("/proc/cpuinfo")
    if err != nil {
        return "", errors.New("cannot read CPU identifier: /sys/class/dmi/id/product_uuid and /proc/cpuinfo both unavailable")
    }
    for _, line := range strings.Split(string(data), "\n") {
        if strings.HasPrefix(line, "Serial") {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 {
                return strings.TrimSpace(parts[1]), nil
            }
        }
    }
    return "", errors.New("CPU serial not found in /proc/cpuinfo")
}
```

#### `getDiskSerial()`

1. Find the root device by reading `/proc/mounts` or using `findmnt -n -o SOURCE /`.
2. Extract the base device name (strip partition number).
3. Read `/sys/block/<device>/serial`.

```go
func getDiskSerial() (string, error) {
    // Find root mount device
    out, err := exec.Command("findmnt", "-n", "-o", "SOURCE", "/").Output()
    if err != nil {
        return "", fmt.Errorf("findmnt failed: %w", err)
    }
    device := strings.TrimSpace(string(out))
    // Strip /dev/ prefix and partition number to get base device
    base := filepath.Base(device)
    base = strings.TrimRight(base, "0123456789")
    base = strings.TrimSuffix(base, "p") // for nvme0n1p1 → nvme0n1

    serial, err := os.ReadFile(fmt.Sprintf("/sys/block/%s/serial", base))
    if err != nil {
        return "", fmt.Errorf("cannot read disk serial for %s: %w", base, err)
    }
    val := strings.TrimSpace(string(serial))
    if val == "" {
        return "", fmt.Errorf("empty disk serial for %s", base)
    }
    return val, nil
}
```

#### `getMachineID()`

Read `/etc/machine-id`. This is a systemd-generated persistent identifier present
on virtually all modern Linux systems.

```go
func getMachineID() (string, error) {
    data, err := os.ReadFile("/etc/machine-id")
    if err != nil {
        return "", fmt.Errorf("cannot read /etc/machine-id: %w", err)
    }
    val := strings.TrimSpace(string(data))
    if val == "" {
        return "", errors.New("/etc/machine-id is empty")
    }
    return val, nil
}
```

---

### macOS — `hardware_darwin.go`

#### `getCPUSerial()`

Use `ioreg` to get the platform serial number.

```go
func getCPUSerial() (string, error) {
    out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
    if err != nil {
        return "", fmt.Errorf("ioreg failed: %w", err)
    }
    // Parse IOPlatformSerialNumber from output
    for _, line := range strings.Split(string(out), "\n") {
        if strings.Contains(line, "IOPlatformSerialNumber") {
            // Format: "IOPlatformSerialNumber" = "XXXXXXXXXXXX"
            parts := strings.SplitN(line, "=", 2)
            if len(parts) == 2 {
                val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
                if val != "" {
                    return val, nil
                }
            }
        }
    }
    return "", errors.New("IOPlatformSerialNumber not found in ioreg output")
}
```

#### `getDiskSerial()`

Use `diskutil info /` and parse the `Disk / Partition UUID` or `Volume UUID` field.

```go
func getDiskSerial() (string, error) {
    out, err := exec.Command("diskutil", "info", "/").Output()
    if err != nil {
        return "", fmt.Errorf("diskutil failed: %w", err)
    }
    // Look for "Volume UUID" or "Disk / Partition UUID"
    for _, line := range strings.Split(string(out), "\n") {
        trimmed := strings.TrimSpace(line)
        if strings.HasPrefix(trimmed, "Volume UUID:") || strings.HasPrefix(trimmed, "Disk / Partition UUID:") {
            parts := strings.SplitN(trimmed, ":", 2)
            if len(parts) == 2 {
                val := strings.TrimSpace(parts[1])
                if val != "" {
                    return val, nil
                }
            }
        }
    }
    return "", errors.New("disk UUID not found in diskutil output")
}
```

#### `getMachineID()`

Use `ioreg` to get the hardware UUID (IOPlatformUUID).

```go
func getMachineID() (string, error) {
    out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
    if err != nil {
        return "", fmt.Errorf("ioreg failed: %w", err)
    }
    for _, line := range strings.Split(string(out), "\n") {
        if strings.Contains(line, "IOPlatformUUID") {
            parts := strings.SplitN(line, "=", 2)
            if len(parts) == 2 {
                val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
                if val != "" {
                    return val, nil
                }
            }
        }
    }
    return "", errors.New("IOPlatformUUID not found in ioreg output")
}
```

---

### Windows — `hardware_windows.go`

All Windows implementations use `exec.Command("wmic", ...)` or PowerShell.

#### `getCPUSerial()`

```go
func getCPUSerial() (string, error) {
    out, err := exec.Command("wmic", "cpu", "get", "ProcessorId", "/format:value").Output()
    if err != nil {
        return "", fmt.Errorf("wmic cpu query failed: %w", err)
    }
    for _, line := range strings.Split(string(out), "\n") {
        if strings.HasPrefix(strings.TrimSpace(line), "ProcessorId=") {
            val := strings.TrimPrefix(strings.TrimSpace(line), "ProcessorId=")
            val = strings.TrimSpace(val)
            if val != "" {
                return val, nil
            }
        }
    }
    return "", errors.New("ProcessorId not found in wmic output")
}
```

#### `getDiskSerial()`

```go
func getDiskSerial() (string, error) {
    // Get the system disk (index 0)
    out, err := exec.Command("wmic", "diskdrive", "where", "Index=0", "get", "SerialNumber", "/format:value").Output()
    if err != nil {
        return "", fmt.Errorf("wmic diskdrive query failed: %w", err)
    }
    for _, line := range strings.Split(string(out), "\n") {
        if strings.HasPrefix(strings.TrimSpace(line), "SerialNumber=") {
            val := strings.TrimPrefix(strings.TrimSpace(line), "SerialNumber=")
            val = strings.TrimSpace(val)
            if val != "" {
                return val, nil
            }
        }
    }
    return "", errors.New("disk serial number not found in wmic output")
}
```

#### `getMachineID()`

Read the `MachineGuid` from the Windows registry.

```go
func getMachineID() (string, error) {
    out, err := exec.Command("reg", "query",
        `HKLM\SOFTWARE\Microsoft\Cryptography`,
        "/v", "MachineGuid").Output()
    if err != nil {
        return "", fmt.Errorf("registry query failed: %w", err)
    }
    for _, line := range strings.Split(string(out), "\n") {
        if strings.Contains(line, "MachineGuid") {
            fields := strings.Fields(line)
            if len(fields) >= 3 {
                return fields[len(fields)-1], nil
            }
        }
    }
    return "", errors.New("MachineGuid not found in registry")
}
```

---

## Keystore — `internal/keystore/keystore.go`

### Interface

```go
type Keystore interface {
    Store(key string, data []byte) error
    Retrieve(key string) ([]byte, error)
    Delete(key string) error
}
```

### Implementation

Uses `go-keyring` with a fixed service name `"sentinel-drm"`.

```go
const serviceName = "sentinel-drm"

type osKeystore struct{}

func New() Keystore {
    return &osKeystore{}
}

func (k *osKeystore) Store(key string, data []byte) error {
    // go-keyring stores strings, so base64-encode binary data
    encoded := base64.StdEncoding.EncodeToString(data)
    return keyring.Set(serviceName, key, encoded)
}

func (k *osKeystore) Retrieve(key string) ([]byte, error) {
    encoded, err := keyring.Get(serviceName, key)
    if err != nil {
        return nil, err
    }
    return base64.StdEncoding.DecodeString(encoded)
}

func (k *osKeystore) Delete(key string) error {
    return keyring.Delete(serviceName, key)
}
```

### Well-Known Keys

These are the key names used throughout the application:

```go
const (
    KeyMachinePrivateKey  = "machine-private-key"
    KeyStateEncryptionKey = "state-encryption-key"
)
```

---

## Done Criteria

- [ ] `CollectFingerprint()` returns a consistent SHA-256 hex string on the same machine
- [ ] Each component function (`getCPUSerial`, `getDiskSerial`, `getMachineID`) returns
  non-empty values
- [ ] Missing hardware components produce clear error messages (no silent fallbacks)
- [ ] Keystore `Store` / `Retrieve` roundtrip works for binary data
- [ ] Keystore `Retrieve` returns appropriate error for non-existent keys
- [ ] Keystore `Delete` removes stored data
- [ ] `go-keyring` dependency added to `go.mod` ← user action required
