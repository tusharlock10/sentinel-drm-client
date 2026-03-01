# Sentinel DRM Client — Detailed Implementation Plan

**Status**: Complete
**Last Updated**: 2026-03-01
**Phases Complete**: 1, 2, 3, 5, 6, 7, 8, 9
**Phases Removed**: 4 (Encrypted State File — client is now stateless)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Phase 1 — Project Skeleton, CLI, Crypto Primitives](#3-phase-1--project-skeleton-cli-crypto-primitives)
4. [Phase 2 — License File Parsing and Verification](#4-phase-2--license-file-parsing-and-verification)
5. [Phase 3 — Hardware Fingerprint](#5-phase-3--hardware-fingerprint)
6. [Phase 5 — DRM Server Communication](#7-phase-5--drm-server-communication)
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
- Communicates with the Sentinel DRM backend for registration and periodic heartbeats
  (STANDARD licenses); the client is stateless — no state is persisted between runs
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
│   ├── hardware/                  # Hardware fingerprint collection (HARDWARE_BOUND only)
│   │   ├── hardware.go            # CollectFingerprint()
│   │   ├── hardware_linux.go
│   │   ├── hardware_darwin.go
│   │   └── hardware_windows.go
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
Phase 3: hardware                      (no deps — HARDWARE_BOUND fingerprint only)
Phase 5: drm                           (depends on: crypto)
Phase 6: process, ipc                  (no deps)
Phase 7: sentinel orchestrator         (depends on: ALL above)
Phase 8: antitamper, Makefile          (depends on: ipc, sentinel)
```
Note: Phase 4 (Encrypted State File) was removed. The client is stateless — no
keystore, no machine EC keypair, no activation state is persisted between runs.

### Startup Flows

**STANDARD license:**
1. Parse CLI flags → 2. Load/verify license file → 3. Register with DRM server →
4. Verify signed response; if status is not ACTIVE, exit with error →
5. Verify software binary checksum → 6. Launch software → 7. Start IPC server →
8. Start heartbeat loop → 9. Start anti-tamper monitoring → 10. Monitor process

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
    Version      string // set from -ldflags "-X main.version=..." at build time; empty in dev builds
}

func (c *Config) Validate() error
```

Validation: license and software paths must exist on disk. `Version` is not validated
(empty is valid for development builds).

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

## 5. Phase 3 — Hardware Fingerprint ✓

### Files

- `internal/hardware/hardware.go` — `CollectFingerprint()` + SHA-256
- `internal/hardware/hardware_linux.go`
- `internal/hardware/hardware_darwin.go`
- `internal/hardware/hardware_windows.go`

### Fingerprint Logic

```go
func CollectFingerprint() (string, error)
```

`CollectFingerprint` returns `SHA256Hex(cpuSerial + diskSerial + machineID)`.
Used only for HARDWARE_BOUND license verification. Not used for STANDARD licenses.

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

---


## 7. Phase 5 — DRM Server Communication

### Files

- `internal/drm/drm.go`

### Security Model

The client does **not** sign requests. The server is the source of truth and HTTPS
is the transport security layer. The client verifies every server **response** using
the org's EC public key embedded in the binary — this prevents a MITM from forging
or replaying responses (e.g., injecting a fake `REVOKED` to DoS, or suppressing a
real `REVOKED` to keep a dead license running).

### Response Verification

Every response from the backend is a signed envelope:

```json
{"payload": "<base64url(canonical_json)>", "sig": "<base64url(ecdsa_sig)>"}
```

Verification: `crypto.VerifyECDSA(orgPubKey, []byte(envelope.Payload), sigBytes)`
— signature is over the raw base64url payload string, not the decoded JSON.

The `request_nonce` in the decoded response payload MUST match the nonce sent in
`X-Sentinel-Nonce`. This binds the response to the specific request and prevents
replay of old signed responses.

### Endpoints

#### POST `/api/v1/drm/register/`

Called once at startup for STANDARD licenses. Creates an ephemeral `LicenseMachine`
record on the server and returns a session token held in memory for the process lifetime.

**Request headers:** `Content-Type: application/json`, `X-Sentinel-Nonce: <uuid>`

**Request body:**
```json
{
  "license_key": "SENTINEL-XXXX-XXXX-XXXX-XXXX",
  "platform": "LINUX_AMD64",
  "software_version": "2.1.4"
}
```

**Response payload (always a signed 200):**
```json
{
  "status": "ACTIVE",
  "token": "<uuid — LicenseMachine.token, or null if not ACTIVE>",
  "request_nonce": "<reflected>"
}
```

- `status` reflects the current license status. If anything other than `ACTIVE`,
  `token` is null and the sentinel client logs the status and exits immediately.
- `404` is returned for licenses not found or that are not STANDARD type.
- Max-machines enforcement does **not** happen at registration; it happens at the
  first heartbeat. A new machine gets up to one full heartbeat interval to begin
  heartbeating before enforcement fires.

#### GET `/api/v1/drm/heartbeat/`

Called periodically by STANDARD license software at `heartbeat_interval_minutes`
interval. Any failure (network or server error) causes immediate shutdown.

**Request headers:** `X-Sentinel-Token: <token>`, `X-Sentinel-Nonce: <uuid>`

**No request body.**

**Response payload (signed):**
```json
{
  "status": "ACTIVE",
  "request_nonce": "<reflected>"
}
```

**Status values and required software action:**

| Status | Action |
|---|---|
| `ACTIVE` | Continue normal operation |
| `REVOKED` | Log status and shut down immediately |
| `EXPIRED` | Log status and shut down immediately |
| `SUSPENDED` | Log status and shut down immediately |
| `DECOMMISSIONED` | Log status and shut down immediately |

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
    orgPubKey  *ecdsa.PublicKey
    httpClient *http.Client
}

type RegisterRequest struct {
    LicenseKey      string `json:"license_key"`
    Platform        string `json:"platform"`
    SoftwareVersion string `json:"software_version"`
}

type RegisterResponse struct {
    Status       string `json:"status"`
    Token        string `json:"token"`
    RequestNonce string `json:"request_nonce"`
}

type HeartbeatResponse struct {
    Status       string `json:"status"`
    RequestNonce string `json:"request_nonce"`
}

func NewClient(serverURL string, orgPubKey *ecdsa.PublicKey) *Client
func (c *Client) Register(req RegisterRequest) (*RegisterResponse, error)
func (c *Client) Heartbeat(token string) (*HeartbeatResponse, error)
```

---

## 8. Phase 6 — Process Management and IPC ✓

### Files (Process)

- `internal/process/process.go` — Manager, Launch, Wait, Exited, Signal, VerifyBinaryChecksum
- `internal/process/process_unix.go` — Stop() with SIGTERM → 10s → SIGKILL
- `internal/process/process_windows.go` — Stop() with direct Kill() (no SIGTERM on Windows)

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

- `internal/ipc/ipc.go` — protocol types, Server, Serve, SocketPath helper, degradation stubs
- `internal/ipc/ipc_unix.go` — Unix domain socket listener (Linux/macOS)
- `internal/ipc/ipc_windows.go` — Named pipe listener via `github.com/Microsoft/go-winio` (Windows)

### IPC Protocol

AES-256-GCM encrypted, newline-delimited. Every message (request and response) is
encrypted with a 32-byte shared key (`internal/ipc/ipc_key.go`, gitignored). The
wire format for each line is:

```
<nonce_hex>.<ciphertext_hex>\n
```

- Nonce: 12 random bytes, hex-encoded (new random nonce per message)
- Ciphertext: AES-256-GCM-encrypted JSON + 16-byte authentication tag, hex-encoded

A connection that sends a line that fails AES-GCM decryption (wrong key or tampered
message) is dropped immediately with no response. This is how the software verifies it
is connected to the real sentinel binary — only sentinel knows the shared key.

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

### IPC Key (`internal/ipc/ipc_key.go`)

A gitignored Go file containing the 32-byte AES-256-GCM key as a `[32]byte` variable.
Generated once per `(org, software)` build by QNu Labs. The identical key is embedded
in the consumer software (e.g. `ipc_key.py`) and passed to the Python SDK at runtime.

```go
// internal/ipc/ipc_key.go  (gitignored)
package ipc
var ipcKey = [32]byte{0x01, 0x02, ...}  // 32 bytes; garble obfuscates this at build time
```

To generate a new key:
```bash
python3 -c "import os; key=os.urandom(32); print(', '.join(f'0x{b:02x}' for b in key))"
```

### IPC Socket Path

Both license flows (STANDARD and HARDWARE_BOUND) use a **random UUID** for the
socket path. The fingerprint (HARDWARE_BOUND) is used only for license verification,
not for the socket name, making the path unpredictable.

| OS | Path |
|---|---|
| Linux/macOS | `/tmp/sentinel-<session_uuid>.sock` |
| Windows | `\\.\pipe\sentinel-<session_uuid>` |

### Server

```go
func SocketPath(machineID string) string  // "/tmp/sentinel-<id>.sock" or "\\.\pipe\sentinel-<id>"

func NewServer(socketPath string, info *LicenseInfo) (*Server, error)
func (s *Server) Serve(ctx context.Context) error
func (s *Server) Close() error
func (s *Server) SetDegradeStage(stage DegradeStage) // for anti-tamper (Phase 8)
```

Multiple concurrent connections are accepted; each is handled in its own goroutine
reading JSON lines and writing JSON line responses.

---

## 9. Phase 7 — Main Orchestrator ✓

### Files

- `internal/sentinel/sentinel.go`

### Orchestrator

```go
type Sentinel struct {
    config    *config.Config
    orgPubKey *ecdsa.PublicKey
    license   *license.LicensePayload
    process   *process.Manager
    ipcServer *ipc.Server
}

func New(cfg *config.Config, orgPubKey *ecdsa.PublicKey) *Sentinel
func (s *Sentinel) Run(ctx context.Context) error

// SetupSignalHandler is a package-level function (not a method). Called from main.go
// before constructing the Sentinel, so the context is available for Run().
func SetupSignalHandler() (context.Context, context.CancelFunc)
```

### STANDARD License Flow

1. Load and verify license file (signature + expiry)
2. Create DRM client using `*license.ServerURL` (embedded in license file, not a CLI flag)
3. Call `drm.Register()`. Verify signed response. If `status != "ACTIVE"`, log status
   and exit immediately. On success, hold `token` in memory for this process lifetime.
4. Generate a session UUID for the IPC socket path (local-only, not sent to server)
5. Launch software process; pass `SENTINEL_IPC_SOCKET` env var
6. Start IPC server in a goroutine
7. Start heartbeat loop in a goroutine
8. Start anti-tamper monitoring (Phase 8)
9. Wait for: software exit OR heartbeat failure OR signal

### HARDWARE_BOUND License Flow

1. Load and verify license file (signature + expiry)
2. Collect hardware fingerprint
3. Compare with `license.HardwareFingerprint` — must match exactly
4. Launch software process; use fingerprint as IPC socket name
5. Start IPC server
6. Start anti-tamper monitoring (Phase 8)
7. Wait for software exit or signal — fully offline, no server communication

### Heartbeat Loop

```go
func (s *Sentinel) heartbeatLoop(ctx context.Context, token string, drmClient *drm.Client)
```

- Runs on a `time.Ticker` at `heartbeat_interval_minutes` from the license file
- **Any error** (connection failure or server error): log error and immediately call
  `s.process.Stop()` and return. There is no grace period or retry.
- **`status != "ACTIVE"`**: log the status and immediately call `s.process.Stop()` and return
- **`status == "ACTIVE"`**: continue to next tick

### Signal Handling

`SetupSignalHandler()` is a package-level function called from `main.go`. It returns
a cancellable context that is passed into `Run()`.

On SIGINT/SIGTERM:
1. Context is cancelled → heartbeat loop returns, IPC Serve returns
2. Main select picks up `ctx.Done()` → closes IPC server, calls `proc.Stop()`
3. Sentinel exits

---

## 10. Phase 8 — Anti-Tamper, Degradation, and Build System ✓

### Files (Anti-Tamper)

- `internal/antitamper/antitamper.go` — orchestrator + degradation state machine
- `internal/antitamper/antitamper_linux.go` — TracerPid check
- `internal/antitamper/antitamper_darwin.go` — sysctl P_TRACED check
- `internal/antitamper/antitamper_windows.go` — IsDebuggerPresent check
- `internal/antitamper/antitamper_other.go` — no-op fallback for unsupported platforms
- `internal/sentinel/sentinel.go` — modified: monitor started after IPC server in both license flows
- `cmd/sentinel/main.go` — modified: unescape PEM newlines embedded by Makefile

### Detection Methods

| Check | Linux | macOS | Windows |
|---|---|---|---|
| Debugger attached | `/proc/self/status` TracerPid field | `unix.SysctlKinfoProc` → `info.Proc.P_flag & pTraced` | `IsDebuggerPresent()` + `CheckRemoteDebuggerPresent()` via `kernel32.dll` |

Periodic checks every 5-10 seconds with random jitter to avoid predictable timing.
Initial check also runs at startup before the loop.

**macOS implementation note**: `KERN_PROC`, `KERN_PROC_PID`, and `P_TRACED` are not
exported by `golang.org/x/sys/unix`. Use `unix.SysctlKinfoProc("kern.proc.pid", pid)`
and the local constant `pTraced = 0x00000800`. The struct field is `info.Proc.P_flag`
(type `ExternProc`, not `Kproc`).

**Linux implementation note**: Only the TracerPid check is used. The ptrace self-check
(`PTRACE_TRACEME`) was rejected as unsafe in Go's multithreaded runtime.

### Degradation State Machine

On tamper detection, DO NOT immediately kill. Progress through degradation stages:

```go
type DegradeStage int
const (
    StageNormal   DegradeStage = iota
    StageWarnings               // cryptic warning messages to stderr
    StageErrors                 // inject errors into IPC responses
    StageSlowdown               // increased CPU/memory usage
    StageCrash                  // eventual self-crash (exit 137)
)
```

**Timeline after detection (with ±30s random jitter per stage transition):**

| Time | Stage | Behavior |
|---|---|---|
| 0-2 min | `StageWarnings` | Cryptic log messages to stderr every 15-30s |
| 2-5 min | `StageErrors` | IPC errors + escalated error messages to stderr |
| 5-10 min | `StageSlowdown` | 50 MB memory allocation + 2 CPU busy-loop goroutines |
| 10+ min | `StageCrash` | Random 0-60s delay then `os.Exit(137)` |

The ±30s jitter is applied in `progressDegradation` on every call:
`adjustedElapsed = time.Since(detectedAt) + rand.Intn(61)-30 seconds`.

### Warning Emission

Warning messages are emitted by a **separate goroutine** (`warningLoop`) started by
`onDetected` when tampering is first detected. The loop reads the current stage on
each iteration and escalates from warning to error messages when `StageErrors` is
reached.

### IPC Degradation

When `StageErrors` or beyond, IPC responses degrade (implemented in Phase 6 `ipc.go`):
- `get_features` returns empty features map
- `get_license` intermittently returns `{status: "error", error: "license validation failed"}`
- ~30% of all requests fail with a random system error string

### Anti-Tamper Monitor

```go
type Monitor struct { ... }

func NewMonitor(ipcServer *ipc.Server) *Monitor
func (m *Monitor) Start(ctx context.Context)   // run in goroutine
func (m *Monitor) IsCompromised() bool
```

### Build System (Makefile)

The Makefile accepts the org public key as a **file path** to avoid shell quoting
issues with multiline PEM strings. The file is read and its newlines are escaped to
literal `\n` by `awk` before being passed to `-ldflags`. `cmd/sentinel/main.go`
unescapes `\n` → real newlines at startup before parsing the key.

```makefile
ORG_PUBLIC_KEY_PEM_FILE ?=

_PEM_ESCAPED := $(if $(ORG_PUBLIC_KEY_PEM_FILE),\
    $(shell awk 'BEGIN{ORS="\\n"} 1' "$(ORG_PUBLIC_KEY_PEM_FILE)"),)

LDFLAGS := -X 'main.orgPublicKeyPEM=$(_PEM_ESCAPED)' \
           -X 'main.version=$(VERSION)'
```

**Usage:**
```bash
make build ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem            # dev
make build-prod ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem VERSION=1.0.0  # production
make build-all  ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem VERSION=1.0.0  # all 5 platforms
```

Garble flags:
- `-literals` — obfuscate string literals (hides embedded public key, error messages)
- `-tiny` — strip extra info
- `-seed=random` — randomize obfuscation per build

**Go version requirement**: Pinned to Go 1.25.7 (`go 1.25.0` + `toolchain go1.25.7`
in `go.mod`). Garble v0.15.0 does not support Go 1.26+. Do not upgrade Go past 1.25
until garble releases support for the new version.

---

## 11. Dependencies

External Go dependencies:

| Dependency | Purpose | Added |
|---|---|---|
| `github.com/spf13/cobra` | CLI framework — single root command with flags | Phase 1 |
| `github.com/google/uuid` | UUID v4 generation for request nonces and IPC session IDs | Phase 5 |
| `github.com/Microsoft/go-winio` | Windows named pipe IPC (`\\.\pipe\...`); build-tagged Windows-only | Phase 6 |
| `mvdan.cc/garble` | Binary obfuscation (build tool only, not a library dependency) | Phase 8 |

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

Phase 3 ✓ Hardware fingerprint (HARDWARE_BOUND only)
          ├── internal/hardware/hardware.go         CollectFingerprint()
          ├── internal/hardware/hardware_linux.go   DMI UUID / cpuinfo, findmnt+sysfs, machine-id
          ├── internal/hardware/hardware_darwin.go  ioreg, diskutil, ioreg UUID
          └── internal/hardware/hardware_windows.go PowerShell Get-CimInstance, registry
          Note: keystore package removed (client is stateless)

Phase 4   REMOVED — Encrypted State File
          The client is stateless. No machine EC keypair, no activation state,
          no grace period is persisted between process runs.

Phase 5 ✓ DRM server communication
          ├── internal/drm/drm.go          register + heartbeat with response verification
          └── internal/drm/drm_test.go     12 tests, all passing (httptest mock backend)

Phase 6 ✓ Process management and IPC
          ├── internal/process/process.go         launch, monitor, stop, checksum verification
          ├── internal/process/process_unix.go    Stop() — SIGTERM → 10s → SIGKILL
          ├── internal/process/process_windows.go Stop() — direct Kill()
          ├── internal/process/process_test.go    5 tests, all passing
          ├── internal/ipc/ipc.go                 protocol types, server, SocketPath()
          ├── internal/ipc/ipc_unix.go            Unix domain socket listener
          ├── internal/ipc/ipc_windows.go         named pipe listener (go-winio)
          ├── internal/ipc/ipc_test.go            7 tests, all passing
          ├── internal/ipc/ipc_unix_test.go       dialSocket helper (Linux/macOS)
          └── internal/ipc/ipc_windows_test.go    dialSocket helper (Windows)

Phase 7 ✓ Main orchestrator
          ├── internal/sentinel/sentinel.go  STANDARD + HARDWARE_BOUND flows,
          │                                  heartbeat loop (any failure = immediate shutdown),
          │                                  signal handling
          ├── internal/config/config.go      added Version field (threaded from main ldflags var)
          └── cmd/sentinel/main.go           wired: SetupSignalHandler(), sentinel.New(), Run()

Phase 8 ✓ Anti-tamper, degradation, and build system
          ├── internal/antitamper/antitamper.go         Monitor struct, degradation state machine
          ├── internal/antitamper/antitamper_linux.go   TracerPid check (/proc/self/status)
          ├── internal/antitamper/antitamper_darwin.go  sysctl KinfoProc P_TRACED check
          ├── internal/antitamper/antitamper_windows.go IsDebuggerPresent + CheckRemoteDebuggerPresent
          ├── internal/antitamper/antitamper_other.go   no-op fallback for unsupported platforms
          ├── internal/sentinel/sentinel.go             wired antitamper monitor (both license flows)
          └── Makefile                                  garble builds, cross-compilation (5 platforms)

Phase 9 ✓ IPC authentication (AES-GCM) + Python SDK
          ├── internal/ipc/ipc_key.go      (gitignored) shared AES-256-GCM key [32]byte
          ├── internal/ipc/ipc.go          encryptMessage/decryptMessage; handleConnection
          │                                updated to encrypt all responses and drop connections
          │                                that fail decryption (unauthenticated clients)
          ├── internal/ipc/ipc_test.go     TestServerServe updated for encrypted protocol
          ├── internal/sentinel/sentinel.go runHardwareBound: socket path now uses random UUID
          │                                (was fingerprint — predictable; now unpredictable)
          ├── .gitignore                   added internal/ipc/ipc_key.go pattern
          └── sentinel-drm-python-sdk/     companion Python SDK (separate repo)
              ├── src/sentinel_sdk/__init__.py  exports sentinel_protect_me_uwu
              └── src/sentinel_sdk/_sdk.py      AES-GCM IPC client, PPID check, health thread
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
| Client statefulness | Stateless — no keystore, no state file, no machine EC keypair | Simplifies client; server is the sole source of truth |
| Heartbeat failure | Any failure = immediate shutdown, no grace period | Customer accepts risk of network interruption; simpler and harder to abuse |
| Max-machines enforcement | Enforced server-side at first heartbeat, not at registration | Allows legitimate restarts without waiting for a slot to free up |
| Session token | UUID generated by server per registration, held in memory | Simple; no key material on disk; lost on process exit which is correct |
| Request authentication | No client-side request signing; HTTPS only | Server signs all responses; response forgery/replay protection still exists |
| Process management | Direct exec with monitoring | Simple, reliable, sentinel exits when software exits |
| Binary verification | SHA-256 from license payload | Prevents patched binaries (pending backend field) |
| Canonical JSON | Sorted keys, compact, ASCII-only | Must be byte-identical with Python backend output |
| Obfuscation | garble with -literals -tiny | Hides string literals and embedded keys in binary |
| Anti-tamper Linux | TracerPid only (no ptrace self-check) | ptrace PTRACE_TRACEME is unsafe in Go's multithreaded runtime |
| Anti-tamper macOS | `unix.SysctlKinfoProc` + `info.Proc.P_flag` | High-level wrapper; raw Syscall6 approach had unexported constant names |
| PEM embedding in ldflags | File path + awk newline escaping + runtime unescape | `-ldflags -X` cannot handle multiline strings; awk converts `\n` → `\n` literal |
| Go version pinned | go 1.25.0 + toolchain go1.25.7 | garble v0.15.0 requires Go ≤ 1.25; toolchain directive prevents silent upgrades |
| IPC authentication | AES-256-GCM shared key (gitignored `ipc_key.go`) | No key embedding in binary at build time from external tooling; key baked in directly; garble obfuscates it; equivalent security to challenge-response with embedded key |
| IPC wire format | `<nonce_hex>.<ciphertext_hex>\n` | Hex chosen over base64 — no padding edge cases; symmetric with Python's `bytes.fromhex` |
| Unauthenticated IPC connections | Drop connection silently (no error response) | Sending an encrypted error would confirm the socket exists and is sentinel |
| HARDWARE_BOUND socket path | Random UUID (was fingerprint) | Hardware fingerprint is deterministic and pre-computable; random UUID prevents socket path prediction |
| Software PPID check | Checked every 30s in Python SDK health thread | Detects sentinel being killed and software being re-parented to init/launchd |
| Background thread hard exit | `os._exit(1)` not `sys.exit()` | `SystemExit` from non-main threads does not terminate the process in Python |
