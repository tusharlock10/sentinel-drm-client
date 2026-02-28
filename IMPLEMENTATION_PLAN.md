# Sentinel DRM Client — Detailed Implementation Plan

**Status**: In Progress
**Last Updated**: 2026-02-28
**Phases Complete**: 1, 2, 3, 4

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Phase 1 — Project Skeleton, CLI, Crypto Primitives](#3-phase-1--project-skeleton-cli-crypto-primitives)
4. [Phase 2 — License File Parsing and Verification](#4-phase-2--license-file-parsing-and-verification)
5. [Phase 3 — Hardware Fingerprint and OS Keystore](#5-phase-3--hardware-fingerprint-and-os-keystore)
6. [Phase 4 — Encrypted State File](#6-phase-4--encrypted-state-file)
7. [Phase 5 — DRM Server Communication](#7-phase-5--drm-server-communication)
8. [Phase 6 — Process Management and IPC](#8-phase-6--process-management-and-ipc)
9. [Phase 7 — Main Orchestrator](#9-phase-7--main-orchestrator)
10. [Phase 8 — Anti-Tamper, Degradation, and Build System](#10-phase-8--anti-tamper-degradation-and-build-system)
11. [Dependencies](#11-dependencies)
12. [Backend Changes Required](#12-backend-changes-required)
13. [Implementation Sequence](#13-implementation-sequence)
14. [Design Decisions Summary](#14-design-decisions-summary)

---

## 1. Overview

The Sentinel DRM Client is a Go binary that enforces software licensing on customer
machines. It is built per-organization with the organization's EC P-256 public key
embedded at compile time via `-ldflags`. The client:

- Validates license files offline (signature verification with embedded public key)
- Launches licensed software as a child process
- Communicates with the Sentinel DRM backend for activation and periodic heartbeats
  (STANDARD licenses)
- Validates hardware fingerprints locally (HARDWARE_BOUND licenses, fully air-gapped)
- Provides license metadata to the running software over IPC
- Protects against debugging, patching, and tampering

### Customer-Facing Components

```
1. Software Binary    — the actual product (DRM-unaware, generic per platform)
2. Sentinel Client    — Go binary with org's EC public key embedded; validates
                        the license file and launches the software
3. License File (.lic) — signed with the org's EC private key
```

The customer downloads all three, places them on a machine, and runs:
```
sentinel --license /path/to/license.lic --software /path/to/binary
```
The server URL (for STANDARD licenses) is embedded in the license file itself.

---

## 2. Architecture

### Package Structure

```
sentinel-drm-client/
├── cmd/sentinel/main.go          # Entry point, cobra root command, embedded public key
├── internal/
│   ├── config/                    # CLI flags, parsed configuration struct
│   │   └── config.go
│   ├── crypto/                    # EC key ops, ECDSA sign/verify, base64url, canonical JSON
│   │   └── crypto.go
│   ├── license/                   # License file parsing, payload validation, signature verification
│   │   └── license.go
│   ├── hardware/                  # Hardware fingerprint collection
│   │   ├── hardware.go            # Interface + fingerprint computation
│   │   ├── hardware_linux.go
│   │   ├── hardware_darwin.go
│   │   └── hardware_windows.go
│   ├── keystore/                  # File-based AES-256-GCM keystore
│   │   └── keystore.go            # Vault key passed in by caller (derived in Phase 7)
│   ├── state/                     # Encrypted local state file management
│   │   └── state.go
│   ├── drm/                       # DRM server communication
│   │   └── drm.go
│   ├── process/                   # Software process lifecycle management
│   │   └── process.go
│   ├── ipc/                       # IPC server (Unix socket / named pipe)
│   │   ├── ipc.go                 # Protocol definition + server logic
│   │   ├── ipc_unix.go            # Unix domain socket (Linux/macOS)
│   │   └── ipc_windows.go         # Named pipes (Windows)
│   ├── antitamper/                # Anti-debugging, degradation logic
│   │   ├── antitamper.go          # Orchestrator + degradation state machine
│   │   ├── antitamper_linux.go
│   │   ├── antitamper_darwin.go
│   │   └── antitamper_windows.go
│   └── sentinel/                  # Main orchestrator
│       └── sentinel.go
├── go.mod
├── go.sum
└── Makefile                       # Build with garble, cross-compilation
```

### Dependency Graph (build order)

```
Phase 1: config, crypto               (no deps)
Phase 2: license                       (depends on: crypto)
Phase 3: keystore, hardware            (no deps)
Phase 4: state                         (depends on: keystore)
Phase 5: drm                           (depends on: crypto, state)
Phase 6: process, ipc                  (no deps)
Phase 7: sentinel orchestrator         (depends on: ALL above)
Phase 8: antitamper, Makefile          (depends on: ipc, sentinel)
```

### Startup Flows

**STANDARD license:**
1. Parse CLI flags → 2. Load/verify license file → 3. Init keystore →
4. Load/generate machine EC keypair → 5. Load/create state file →
6. Contact server: activate or heartbeat → 7. Verify response signature →
8. Verify software binary checksum → 9. Launch software → 10. Start IPC server →
11. Start heartbeat loop → 12. Start anti-tamper monitoring → 13. Monitor process

**HARDWARE_BOUND license:**
1. Parse CLI flags → 2. Load/verify license file → 3. Collect hardware fingerprint →
4. Compare fingerprint with license → 5. Check expiry date →
6. Verify software binary checksum → 7. Launch software → 8. Start IPC server →
9. Start anti-tamper monitoring → 10. Monitor process
(No server communication, fully offline)

---

## 3. Phase 1 — Project Skeleton, CLI, Crypto Primitives ✓

### Files

- `cmd/sentinel/main.go`
- `internal/config/config.go`
- `internal/crypto/crypto.go`
- `internal/crypto/crypto_test.go`

### CLI (cmd/sentinel/main.go)

Cobra root command with flags. No subcommands.

```go
var orgPublicKeyPEM string // set via -ldflags "-X main.orgPublicKeyPEM=..."
var version string         // set via -ldflags "-X main.version=..."
```

Required flags:
- `--license` (string) — path to the `.lic` file
- `--software` (string) — path to the software binary

At startup, validate that `orgPublicKeyPEM` is non-empty and parseable into an
`*ecdsa.PublicKey`. Exit with a clear error if not (indicates the binary was built
without embedding the org key).

The server URL for STANDARD license heartbeats is embedded inside the license file,
not passed as a CLI flag.

### Config (internal/config/config.go)

```go
type Config struct {
    LicensePath  string
    SoftwarePath string
}

func (c *Config) Validate() error
```

Validation: license and software paths must exist on disk.

### Crypto (internal/crypto/crypto.go)

All cryptographic utility functions used across the project.

**Functions:**

| Function | Description |
|---|---|
| `Base64URLEncode(data []byte) string` | base64url without padding (matches Python's `base64.urlsafe_b64encode(...).rstrip(b"=")`) |
| `Base64URLDecode(s string) ([]byte, error)` | base64url with padding restoration |
| `ParseECPublicKeyPEM(pem string) (*ecdsa.PublicKey, error)` | Parse PEM → EC P-256 public key |
| `ParseECPrivateKeyPEM(pem []byte) (*ecdsa.PrivateKey, error)` | Parse PEM → EC P-256 private key |
| `GenerateECKeyPair() (*ecdsa.PrivateKey, error)` | Generate EC P-256 keypair |
| `ECPublicKeyToPEM(pub *ecdsa.PublicKey) (string, error)` | Public key → PEM string |
| `ECPrivateKeyToPEM(priv *ecdsa.PrivateKey) ([]byte, error)` | Private key → PEM bytes |
| `SignECDSA(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error)` | ECDSA-SHA256, returns DER-encoded sig |
| `VerifyECDSA(publicKey *ecdsa.PublicKey, data []byte, sig []byte) error` | ECDSA-SHA256 verification |
| `CanonicalJSON(v any) ([]byte, error)` | Sorted keys, compact, ASCII-only |
| `SHA256Hex(data []byte) string` | SHA-256 hex digest |
| `SHA256File(path string) (string, error)` | SHA-256 hex digest of a file (streamed) |

**Critical: CanonicalJSON compatibility**

The backend uses Python's `json.dumps(payload, sort_keys=True, separators=(",", ":"),
ensure_ascii=True)`. The Go implementation MUST produce byte-identical output:
- Keys sorted alphabetically at all nesting levels
- Compact separators (no spaces)
- Non-ASCII characters escaped to `\uXXXX`

Go's `encoding/json` already produces compact JSON, but key ordering of `map[string]any`
is not guaranteed. Use a recursive key-sorting approach: marshal to intermediate
representation, sort keys, then serialize. The `ensure_ascii=True` behavior is NOT
automatic in Go — Go's `json.Marshal` emits valid UTF-8 as-is. The output is
post-processed with `escapeNonASCII`, which replaces every rune ≥ 0x80 with its
`\uXXXX` form (UTF-16 surrogate pairs for runes > U+FFFF).

---

## 4. Phase 2 — License File Parsing and Verification

### Files

- `internal/license/license.go`

### License File Format (.lic)

```json
{
  "alg": "ES256",
  "payload": "<base64url(canonical_json)>",
  "sig": "<base64url(ecdsa_sig)>"
}
```

The signature is over the **base64url string** (the `payload` field value), NOT the
decoded JSON. This matches the backend's signing implementation.

### Structs

```go
type LicenseEnvelope struct {
    Alg     string `json:"alg"`
    Payload string `json:"payload"`
    Sig     string `json:"sig"`
}

type LicenseType string
const (
    LicenseTypeStandard      LicenseType = "STANDARD"
    LicenseTypeHardwareBound LicenseType = "HARDWARE_BOUND"
)

type LicensePayload struct {
    V           int            `json:"v"`
    LicenseKey  string         `json:"license_key"`
    OrgID       string         `json:"org_id"`
    SoftwareID  string         `json:"software_id"`
    LicenseType LicenseType    `json:"license_type"`
    IssueDate   string         `json:"issue_date"`  // "YYYY-MM-DD" — license becomes active on this date
    ExpiryDate  string         `json:"expiry_date"` // "YYYY-MM-DD" — last valid day (inclusive)
    MaxMachines int            `json:"max_machines"`
    Features    map[string]any `json:"features"`

    // STANDARD only
    ServerURL                *string `json:"server_url,omitempty"`                 // DRM backend base URL
    HeartbeatIntervalMinutes *int    `json:"heartbeat_interval_minutes,omitempty"`
    HeartbeatGracePeriodDays *int    `json:"heartbeat_grace_period_days,omitempty"`

    // HARDWARE_BOUND only
    HardwareFingerprint *string `json:"hardware_fingerprint,omitempty"`
}
```

### Functions

**`LoadAndVerify(path string, orgPubKey *ecdsa.PublicKey) (*LicensePayload, error)`**

1. Read `.lic` file from disk
2. JSON unmarshal into `LicenseEnvelope`
3. Verify `alg` is `"ES256"`
4. Base64url-decode the `sig` field
5. Verify signature: `crypto.VerifyECDSA(orgPubKey, []byte(envelope.Payload), sigBytes)`
   — signature is over the raw base64url string bytes
6. Base64url-decode the `payload` field
7. JSON unmarshal into `LicensePayload`
8. Validate payload: call `validatePayload()` which checks:
   - `v` == 1, required string fields non-empty, `license_type` is known, `max_machines` >= 1
   - `issue_date` and `expiry_date` parse as `"YYYY-MM-DD"`
   - today (UTC) >= `issue_date` — dormancy gate; fail: `"license is not yet active (activates: ...)"`
   - today (UTC) <= `expiry_date` — expiry gate; `expiry_date` is the last valid day inclusive
   - STANDARD: `server_url` non-empty, heartbeat fields non-nil and positive, no `hardware_fingerprint`
   - HARDWARE_BOUND: `hardware_fingerprint` non-empty, no heartbeat fields
9. Return the parsed payload

---

## 5. Phase 3 — Hardware Fingerprint and File-Based Keystore ✓

### Files (Hardware)

- `internal/hardware/hardware.go` — `CollectFingerprint()` + `GetMachineID()` + SHA-256
- `internal/hardware/hardware_linux.go`
- `internal/hardware/hardware_darwin.go`
- `internal/hardware/hardware_windows.go`

### Fingerprint Logic

```go
func CollectFingerprint() (string, error)
func GetMachineID() (string, error)
```

`CollectFingerprint` returns `SHA256Hex(cpuSerial + diskSerial + machineID)`.
`GetMachineID` exposes the platform machine ID for keystore vault key derivation in Phase 7.

**Platform-specific collection:**

| Component | Linux | macOS | Windows |
|---|---|---|---|
| CPU Serial | `/sys/class/dmi/id/product_uuid` (primary), `/proc/cpuinfo` Serial (ARM fallback) | `ioreg -rd1 -c IOPlatformExpertDevice` → IOPlatformSerialNumber | PowerShell `Get-CimInstance Win32_Processor` → ProcessorId |
| Disk Serial | `findmnt -n -o SOURCE /` → `/sys/block/<device>/serial` | `diskutil info /` → Volume UUID | PowerShell `Get-CimInstance Win32_DiskDrive -Filter 'Index=0'` → SerialNumber |
| Machine ID | `/etc/machine-id` | `ioreg -rd1 -c IOPlatformExpertDevice` → IOPlatformUUID | PowerShell registry `HKLM:\SOFTWARE\Microsoft\Cryptography` → MachineGuid |

Windows uses `powershell.exe -NoProfile -NonInteractive -Command` for all queries.
`wmic` is deprecated/removed on Windows 11; `Get-CimInstance` is the correct replacement.

Each platform function must return clear errors if a component cannot be read.
No fallbacks — fail fast if hardware identity cannot be established.

### Files (Keystore)

- `internal/keystore/keystore.go`

### Keystore API

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

func New(filePath string, vaultKey [32]byte) (Keystore, error)
func DefaultFilePath() (string, error)
func DeriveVaultKey(machineID string) [32]byte
```

File-based AES-256-GCM encrypted keystore. No external dependency.
Each entry stored as `base64(nonce[12] || ciphertext)` in a JSON file.
Writes are atomic (`<path>.tmp` → `os.Rename`). File permissions: `0600`.

`DeriveVaultKey` computes `SHA256("sentinel-drm-keystore:" + machineID)`, tying
the keystore file to the machine. In Phase 7 the orchestrator calls:
`keystore.New(path, keystore.DeriveVaultKey(hardware.GetMachineID()))`.

Stored items:
- `KeyMachinePrivateKey` — EC P-256 private key (PEM-encoded)
- `KeyStateEncryptionKey` — 32 bytes for AES-256-GCM state file encryption

---

## 6. Phase 4 — Encrypted State File

### Files

- `internal/state/state.go`

### State File Location

| OS | Path |
|---|---|
| Linux | `$XDG_DATA_HOME/sentinel-drm/state.enc` (default `~/.local/share/sentinel-drm/state.enc`) |
| macOS | `~/Library/Application Support/sentinel-drm/state.enc` |
| Windows | `%APPDATA%\sentinel-drm\state.enc` |

### State Structure

```go
type State struct {
    MachineID             string `json:"machine_id"`              // UUID v4, generated once
    Activated             bool   `json:"activated"`               // activation succeeded
    LicenseKey            string `json:"license_key"`             // from license file
    LastHeartbeatSuccess  int64  `json:"last_heartbeat_success"`  // unix timestamp
    GraceRemainingSeconds int64  `json:"grace_remaining_seconds"` // total grace quota left
    GraceExhausted        bool   `json:"grace_exhausted"`         // no more grace ever
}
```

### Encryption

- Key: 32 bytes, stored in OS keystore. Generated with `crypto/rand` on first run.
- Algorithm: AES-256-GCM
- On-disk format: `nonce(12 bytes) || ciphertext`
- Atomic writes: write to temp file, then `os.Rename`

### Functions

```go
type StateManager struct { ... }

func NewStateManager(ks keystore.Keystore) (*StateManager, error)
func (sm *StateManager) Load() (*State, error)   // nil if first run
func (sm *StateManager) Save(state *State) error
```

---

## 7. Phase 5 — DRM Server Communication

### Files

- `internal/drm/drm.go`

### Request Signing Protocol

Every request to `/api/v1/drm/` carries these headers:

```
X-Sentinel-Machine-Id:  <machine_id>
X-Sentinel-Timestamp:   <unix epoch seconds, integer string>
X-Sentinel-Nonce:       <UUID v4 string>
X-Sentinel-Signature:   <base64url(DER-encoded ECDSA-SHA256 signature)>
```

**Signing string** (must match backend exactly):

```
{HTTP_METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256_HEX(BODY)}
```

Example:
```
POST
/api/v1/drm/activate/
1708869000
f47ac10b-58cc-4372-a567-0e02b2c3d479
a3f5c9e1d2b3f4a5e6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8
```

The signature is `ECDSA-SHA256(utf-8 bytes of signing string, machine_private_key)`.

### Response Verification

Every response from the backend:

```json
{"payload": "<base64url>", "sig": "<base64url>"}
```

Verification: `crypto.VerifyECDSA(orgPubKey, []byte(response.Payload), sigBytes)`
— signature is over the base64url string, not the decoded JSON.

The `request_nonce` in the decoded response payload MUST match the nonce sent in the
request header. This prevents response replay attacks.

### Endpoints

#### POST `/api/v1/drm/activate/`

Called by STANDARD license software at first startup.

**Request body:**
```json
{
  "license_key": "SENTINEL-XXXX-XXXX-XXXX-XXXX",
  "machine_id": "<client-generated UUID>",
  "machine_public_key_pem": "<EC P-256 public key, PEM>",
  "platform": "LINUX_AMD64",
  "software_version": "2.1.4"
}
```

**Response payload:**
```json
{
  "status": "ACTIVE",
  "machine_id": "...",
  "license_key": "SENTINEL-...",
  "expiry_date": "2026-01-01",
  "heartbeat_interval_minutes": 15,
  "heartbeat_grace_period_days": 3,
  "features": {"max_users": 500},
  "request_nonce": "<reflected>",
  "responded_at": "2025-06-01T10:00:00Z"
}
```

Re-activation (same machine_id): idempotent, updates public key if changed.

**Error responses (400):**
- "License not found."
- "Only STANDARD licenses support activation."
- "License is DRAFT|REVOKED|SUSPENDED|EXPIRED."
- "License has expired."
- "Maximum machine limit reached for this license."

#### POST `/api/v1/drm/heartbeat/`

Called periodically by STANDARD license software.

**Request body:**
```json
{
  "license_key": "SENTINEL-XXXX-XXXX-XXXX-XXXX",
  "machine_id": "<UUID>",
  "software_version": "2.1.4"
}
```

**Response payload:**
```json
{
  "status": "ACTIVE",
  "machine_id": "...",
  "license_key": "...",
  "expiry_date": "2026-01-01",
  "decommission_pending": false,
  "request_nonce": "<reflected>",
  "responded_at": "2025-06-01T10:00:00Z"
}
```

**Status values and required software action:**

| Status | Action |
|---|---|
| `ACTIVE` | Continue normal operation |
| `REVOKED` | Stop immediately; surface error to user |
| `EXPIRED` | Stop immediately; surface expiry message |
| `SUSPENDED` | Stop; display "license suspended — contact vendor" |
| `DECOMMISSION_PENDING` | Finish work; call `/drm/decommission-ack/`; shut down |

#### POST `/api/v1/drm/decommission-ack/`

Called after receiving `decommission_pending: true`.

**Request body:**
```json
{
  "license_key": "...",
  "machine_id": "..."
}
```

**Response payload:**
```json
{
  "status": "DECOMMISSIONED",
  "machine_id": "...",
  "license_key": "...",
  "request_nonce": "<reflected>",
  "responded_at": "..."
}
```

### Platform String Detection

Detected at runtime using `runtime.GOOS` and `runtime.GOARCH`:

| GOOS/GOARCH | Platform String |
|---|---|
| linux/amd64 | `LINUX_AMD64` |
| linux/arm64 | `LINUX_ARM64` |
| windows/amd64 | `WINDOWS_AMD64` |
| windows/arm64 | `WINDOWS_ARM64` |
| darwin/arm64 | `DARWIN_ARM64` |

### Structs

```go
type Client struct {
    serverURL  string
    machineID  string
    machineKey *ecdsa.PrivateKey
    orgPubKey  *ecdsa.PublicKey
    httpClient *http.Client
}

func NewClient(serverURL, machineID string, machineKey *ecdsa.PrivateKey, orgPubKey *ecdsa.PublicKey) *Client
func (c *Client) Activate(req ActivateRequest) (*ActivateResponse, error)
func (c *Client) Heartbeat(req HeartbeatRequest) (*HeartbeatResponse, error)
func (c *Client) DecommissionAck(req DecommissionAckRequest) (*DecommissionAckResponse, error)
```

---

## 8. Phase 6 — Process Management and IPC

### Files (Process)

- `internal/process/process.go`

### Process Management

```go
type Manager struct { ... }

func Launch(binaryPath string, env []string) (*Manager, error)
func (m *Manager) Wait() error
func (m *Manager) Signal(sig os.Signal)
func (m *Manager) Stop() error              // SIGTERM → wait 10s → SIGKILL
func (m *Manager) Exited() <-chan struct{}   // closed when process exits
```

The software binary is launched as a direct child process. If the software crashes,
Sentinel shuts down too.

**Environment variables passed to the software:**
- `SENTINEL_IPC_SOCKET` — path to the IPC socket/pipe

### Software Binary Verification

Before launching, compute SHA-256 of the software binary. The verification function
exists but is not called until the backend adds `software_checksum` to the license
payload.

```go
func VerifyBinaryChecksum(binaryPath string, expectedChecksum string) error
```

### Files (IPC)

- `internal/ipc/ipc.go` — protocol + server logic
- `internal/ipc/ipc_unix.go` — Unix domain socket listener (Linux/macOS)
- `internal/ipc/ipc_windows.go` — Named pipe listener (Windows)

### IPC Protocol

JSON-over-newline. Software connects to the socket, sends JSON-line requests, receives
JSON-line responses.

```go
type Request struct {
    Method string `json:"method"`
}

type Response struct {
    Status   string         `json:"status"`
    Error    string         `json:"error,omitempty"`
    Features map[string]any `json:"features,omitempty"`
    License  *LicenseInfo   `json:"license,omitempty"`
}

type LicenseInfo struct {
    LicenseKey  string         `json:"license_key"`
    LicenseType string         `json:"license_type"`
    ExpiryDate  string         `json:"expiry_date"`
    Features    map[string]any `json:"features"`
    OrgID       string         `json:"org_id"`
    SoftwareID  string         `json:"software_id"`
}
```

**Supported methods:**

| Method | Response |
|---|---|
| `"get_license"` | Full license info |
| `"get_features"` | Just the features map |
| `"health"` | `{"status": "ok"}` |

### IPC Socket Path

| OS | Path |
|---|---|
| Linux/macOS | `/tmp/sentinel-<machine_id>.sock` |
| Windows | `\\.\pipe\sentinel-<machine_id>` |

### Server

```go
type Server struct { ... }

func NewServer(socketPath string, info *LicenseInfo) (*Server, error)
func (s *Server) Serve(ctx context.Context) error
func (s *Server) Close() error
func (s *Server) SetDegradeStage(stage DegradeStage) // for anti-tamper (Phase 8)
```

Accept one connection at a time. Each connection handled in a goroutine reading
JSON lines and writing JSON line responses.

---

## 9. Phase 7 — Main Orchestrator

### Files

- `internal/sentinel/sentinel.go`

### Orchestrator

```go
type Sentinel struct {
    config    *config.Config
    orgPubKey *ecdsa.PublicKey
    license   *license.LicensePayload
    stateMgr  *state.StateManager
    drmClient *drm.Client
    process   *process.Manager
    ipcServer *ipc.Server
}

func New(cfg *config.Config, orgPubKey *ecdsa.PublicKey) (*Sentinel, error)
func (s *Sentinel) Run(ctx context.Context) error
```

### STANDARD License Flow

1. Load and verify license file (signature + expiry)
2. Initialize keystore
3. Load or generate machine EC keypair from keystore
4. Load state file. If first run, generate machine ID (UUID v4), create initial state
5. **Activation**: If `state.Activated == false`, call `drm.Activate()`. On success,
   set `state.Activated = true`, save state
6. **Mandatory startup heartbeat**: Call `drm.Heartbeat()`.
   - If server unreachable:
     - If `grace_remaining_seconds > 0` and `!grace_exhausted`: allow startup,
       begin consuming grace
     - If `grace_exhausted == true`: refuse to start, exit with error
     - If `grace_remaining_seconds <= 0`: refuse to start, exit with error
   - If server responds with non-ACTIVE status:
     - `DECOMMISSION_PENDING`: call `drm.DecommissionAck()`, clean up, exit gracefully
     - `REVOKED`, `EXPIRED`, `SUSPENDED`: exit with appropriate error message
7. Launch software process
8. Start IPC server in a goroutine
9. Start heartbeat loop in a goroutine
10. Start anti-tamper monitoring (Phase 8)
11. Wait for: software exit OR fatal heartbeat failure OR signal

### HARDWARE_BOUND License Flow

1. Load and verify license file (signature + expiry)
2. Collect hardware fingerprint
3. Compare with `license.HardwareFingerprint` — must match exactly
4. Launch software process
5. Start IPC server
6. Start anti-tamper monitoring (Phase 8)
7. Wait for software exit or signal
8. No heartbeat loop, no server communication, fully offline

### Heartbeat Loop

```go
func (s *Sentinel) heartbeatLoop(ctx context.Context) {
    interval := time.Duration(*s.license.HeartbeatIntervalMinutes) * time.Minute
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            resp, err := s.doHeartbeat()
            if err != nil {
                s.consumeGrace(interval)
                if s.isGraceExhausted() {
                    s.shutdown("Grace period exhausted")
                    return
                }
                continue
            }
            s.handleHeartbeatResponse(resp)
        }
    }
}
```

### Grace Period Logic

- **Total grace quota**: `heartbeat_grace_period_days * 24 * 60 * 60` seconds
  (e.g., 3 days = 259,200 seconds)
- **Each missed heartbeat** consumes `heartbeat_interval_minutes * 60` seconds
  from the quota
- **On successful heartbeat**: grace stops being consumed, remaining quota is
  preserved (NOT reset to full)
- **After full exhaustion** (`grace_exhausted = true`): software comes back online
  and works, but next single heartbeat miss = immediate stop (no more grace)
- **Server is source of truth**: client trusts server response
- **Startup always contacts server** (STANDARD licenses): prevents grace abuse
  via restart cycling. If state file is deleted/tampered, startup forces
  re-sync with server

### Signal Handling

On SIGINT/SIGTERM:
1. Cancel context (stops heartbeat loop)
2. Close IPC server
3. Stop software process gracefully (SIGTERM → wait 10s → SIGKILL)
4. Save final state
5. Exit

---

## 10. Phase 8 — Anti-Tamper, Degradation, and Build System

### Files (Anti-Tamper)

- `internal/antitamper/antitamper.go` — orchestrator + degradation state machine
- `internal/antitamper/antitamper_linux.go`
- `internal/antitamper/antitamper_darwin.go`
- `internal/antitamper/antitamper_windows.go`

### Detection Methods

| Check | Linux | macOS | Windows |
|---|---|---|---|
| Debugger attached | `/proc/self/status` TracerPid | `sysctl kern.proc.pid` P_TRACED flag | `IsDebuggerPresent()` + `CheckRemoteDebuggerPresent()` via syscall |

Periodic checks every 5-10 seconds with random jitter to avoid predictable timing.

### Degradation State Machine

On tamper detection, DO NOT immediately kill. Progress through degradation stages:

```go
type DegradeStage int
const (
    StageNormal   DegradeStage = iota
    StageWarnings               // random cryptic warnings to stdout/stderr
    StageErrors                 // random genuine-looking errors
    StageSlowdown               // increased CPU/memory usage
    StageCrash                  // eventual self-crash
)
```

**Timeline after detection (with random jitter):**

| Time | Stage | Behavior |
|---|---|---|
| 0-2 min | `StageWarnings` | Occasional mysterious log messages |
| 2-5 min | `StageErrors` | Inject fake errors into IPC responses |
| 5-10 min | `StageSlowdown` | Allocate memory, spin CPU in goroutines |
| 10+ min | `StageCrash` | Exit with a generic system error |

### IPC Degradation

When `StageErrors` or beyond, IPC responses degrade:
- `get_features` returns partial/empty features
- `get_license` returns errors intermittently
- Random request failures

This signals the managed software to degrade its own service (bad UX, missing
features, random errors), making it harder for crackers to identify the
protection trigger point.

### Anti-Tamper Monitor

```go
type Monitor struct { ... }

func NewMonitor(ipcServer *ipc.Server) *Monitor
func (m *Monitor) Start(ctx context.Context)
func (m *Monitor) IsCompromised() bool
```

### Build System (Makefile)

```makefile
VERSION ?= dev
ORG_PUBLIC_KEY_PEM ?=

LDFLAGS := -X 'main.orgPublicKeyPEM=$(ORG_PUBLIC_KEY_PEM)' \
           -X 'main.version=$(VERSION)'

# Development build (no obfuscation)
build:
    go build -ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

# Production build (garble obfuscation)
build-prod:
    garble -literals -tiny -seed=random build \
        -ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

# Cross-compilation targets (5 platforms)
build-linux-amd64:
    GOOS=linux GOARCH=amd64 garble ... -o bin/sentinel-linux-amd64 ./cmd/sentinel

build-linux-arm64:
    GOOS=linux GOARCH=arm64 garble ... -o bin/sentinel-linux-arm64 ./cmd/sentinel

build-darwin-arm64:
    GOOS=darwin GOARCH=arm64 garble ... -o bin/sentinel-darwin-arm64 ./cmd/sentinel

build-windows-amd64:
    GOOS=windows GOARCH=amd64 garble ... -o bin/sentinel-windows-amd64.exe ./cmd/sentinel

build-windows-arm64:
    GOOS=windows GOARCH=arm64 garble ... -o bin/sentinel-windows-arm64.exe ./cmd/sentinel

build-all: build-linux-amd64 build-linux-arm64 build-darwin-arm64 \
           build-windows-amd64 build-windows-arm64

test:
    go test ./... -v

clean:
    rm -rf bin/
```

Garble flags:
- `-literals` — obfuscate string literals (hides embedded public key, error messages)
- `-tiny` — strip extra info
- `-seed=random` — randomize obfuscation per build

---

## 11. Dependencies

External Go dependencies:

| Dependency | Purpose | Justification |
|---|---|---|
| `github.com/spf13/cobra` | CLI framework | Mentioned in CLAUDE.md. Single root command with flags |
| `github.com/awnumar/memguard` | Secure memory for private keys | Mentioned in CLAUDE.md. Prevents key material from being swapped to disk. Added in Phase 7 when the full key lifecycle is first wired together. |
| `mvdan.cc/garble` | Binary obfuscation | Mentioned in CLAUDE.md. Build tool only, not a library dependency |

Everything else uses Go stdlib: `crypto/ecdsa`, `crypto/elliptic`, `crypto/sha256`,
`crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/json`, `encoding/pem`,
`net`, `os/exec`, `syscall`, etc.

---

## 12. Backend Changes Required

### `software_checksum` in license payload

The license payload should include a `software_checksum` field (SHA-256 hex digest of
the software binary) so the client can verify binary integrity before launching.

This requires a backend change to `license/signing.py`'s `build_license_payload()`
function. Until implemented, the client code has the verification logic but skips
calling it.

### Clock tampering protection

System clock tampering protection is skipped in v1 as it cannot be reliably prevented
at the software level. This will be revisited when working on a hardware-based solution
(e.g., using TPM 2.0 monotonic counters).

---

## 13. Implementation Sequence

Each phase is independently committable and testable.

```
Phase 1 ✓ Project skeleton, CLI, crypto primitives
          ├── cmd/sentinel/main.go        cobra root command, embedded key var
          ├── internal/config/config.go   Config struct, flag parsing, validation
          ├── internal/crypto/crypto.go   base64url, ECDSA, canonical JSON, SHA-256
          └── internal/crypto/crypto_test.go  unit tests (14 tests, all passing)

Phase 2 ✓ License file parsing and verification
          ├── internal/license/license.go      parse .lic, verify sig, extract payload
          └── internal/license/license_test.go 16 tests, all passing

Phase 3 ✓ Hardware fingerprint and file-based keystore
          ├── internal/hardware/hardware.go         CollectFingerprint(), GetMachineID()
          ├── internal/hardware/hardware_linux.go   DMI UUID / cpuinfo, findmnt+sysfs, machine-id
          ├── internal/hardware/hardware_darwin.go  ioreg, diskutil, ioreg UUID
          ├── internal/hardware/hardware_windows.go PowerShell Get-CimInstance, registry
          └── internal/keystore/keystore.go         New(filePath, vaultKey), DeriveVaultKey(),
                                                    DefaultFilePath(), ErrNotFound

Phase 4 ✓ Encrypted state file
          ├── internal/state/state.go      AES-256-GCM encrypted local state
          └── internal/state/state_test.go 11 tests, all passing

Phase 5   DRM server communication
          └── internal/drm/drm.go          activate, heartbeat, decommission-ack
                                           with request signing + response verification

Phase 6   Process management and IPC
          ├── internal/process/process.go  launch, monitor, stop child process
          └── internal/ipc/                Unix socket / named pipe, JSON protocol

Phase 7   Main orchestrator
          └── internal/sentinel/sentinel.go  STANDARD + HARDWARE_BOUND flows,
                                             heartbeat loop, grace period, signals

Phase 8   Anti-tamper, degradation, and build system
          ├── internal/antitamper/          debugger detection, degradation stages
          └── Makefile                      garble builds, cross-compilation
```

---

## 14. Design Decisions Summary

| Decision | Choice | Rationale |
|---|---|---|
| CLI interface | Single command with flags | Simple, no subcommands needed |
| IPC mechanism | Unix socket (Linux/macOS), named pipes (Windows) | Secure, not network-accessible, platform-native |
| Hardware fingerprint | SHA-256(CPU serial + disk serial + machine ID) | Reasonably stable, covers key hardware identifiers |
| Clock tampering | Skipped in v1 | Cannot reliably prevent at software level; revisit with TPM |
| Anti-tamper response | Service degradation | Harder for crackers to identify protection trigger vs immediate kill |
| Grace period | 3-day total quota, server as source of truth | Prevents abuse while allowing legitimate offline operation |
| Process management | Direct exec with monitoring | Simple, reliable, sentinel exits when software exits |
| Binary verification | SHA-256 from license payload | Prevents patched binaries (pending backend field) |
| State encryption key | OS keystore | Most secure, platform-native credential storage |
| Machine keypair storage | OS keystore | Private key never on disk in plaintext |
| Canonical JSON | Sorted keys, compact, ASCII-only | Must be byte-identical with Python backend output |
| Obfuscation | garble with -literals -tiny | Hides string literals and embedded keys in binary |
