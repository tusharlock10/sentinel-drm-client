# Sentinel DRM Client — Complete Lifecycle & Software Integration Guide

This document provides a detailed, end-to-end description of how the Sentinel DRM
Client works, what it contains, how it communicates with your software and the DRM
backend, and everything you need to know to modify your software binary to work
under Sentinel's license enforcement.

---

## Table of Contents

1. [Embedded Data, Secrets and Keys](#1-embedded-data-secrets-and-keys)
2. [License File Format and Contents](#2-license-file-format-and-contents)
3. [Startup Sequence](#3-startup-sequence)
4. [Startup Checks](#4-startup-checks)
5. [How the Software Binary is Launched](#5-how-the-software-binary-is-launched)
6. [IPC Protocol — Communication Between Sentinel and Your Software](#6-ipc-protocol--communication-between-sentinel-and-your-software)
7. [Complete Communication Flow Diagrams](#7-complete-communication-flow-diagrams)
8. [Data Exchanged Between Sentinel and the Software](#8-data-exchanged-between-sentinel-and-the-software)
9. [Tamper Detection and Anti-Debug](#9-tamper-detection-and-anti-debug)
10. [Server Communication and Mutual Signing (HTTPS-Compromised Model)](#10-server-communication-and-mutual-signing-https-compromised-model)
11. [Data Exchanged With the Backend Server](#11-data-exchanged-with-the-backend-server)
12. [Anti-Tamper Degradation — How It Affects Sentinel and Your Software](#12-anti-tamper-degradation--how-it-affects-sentinel-and-your-software)
13. [How Degradation Commands Reach Your Software](#13-how-degradation-commands-reach-your-software)
14. [Software Integration Checklist](#14-software-integration-checklist)

---

## 1. Embedded Data, Secrets and Keys

The sentinel client binary has two values injected at **build time** via Go
`-ldflags -X`:

### 1.1 Organization EC P-256 Public Key (`orgPublicKeyPEM`)

This is the EC P-256 (also known as `prime256v1` or `secp256r1`) public key that
belongs to the organization. It is embedded as a PEM string inside the Go binary.

**How it gets embedded:**

The Makefile reads the PEM file from disk and uses `awk` to replace real newlines
with literal two-character `\n` sequences, because Go ldflags cannot handle
multi-line strings:

```makefile
_PEM_ESCAPED := $(shell awk 'BEGIN{ORS="\\n"} 1' "$(ORG_PUBLIC_KEY_PEM_FILE)")
LDFLAGS := -X 'main.orgPublicKeyPEM=$(_PEM_ESCAPED)'
```

At startup, `main.go` reverses this:

```go
orgPublicKeyPEM = strings.ReplaceAll(orgPublicKeyPEM, `\n`, "\n")
```

**What it is used for:**

- Verifying the ECDSA signature on the `.lic` license file
- Verifying the ECDSA signature on every DRM backend server response

If this key is empty or not a valid EC P-256 key, the binary **refuses to start**
with the error: `this binary was built without an embedded organization public key`.

### 1.2 Version String (`version`)

An informational version string (e.g., `"1.0.0"`, `"dev"`). Sent to the DRM
backend during activation and heartbeat calls. Has no functional impact on the
client itself.

### 1.3 What is NOT in the binary

- **No private keys.** The machine's EC private key is generated at first run and
  stored in an encrypted on-disk keystore (see [Section 4](#4-startup-checks)).
- **No server URLs.** The DRM backend URL comes from the license file payload.
- **No license data.** Licenses are read from the file path provided via CLI flag.
- **No hardcoded feature flags or org-specific configuration.**

### 1.4 Production Obfuscation

Production builds use [garble](https://github.com/burrowers/garble) with flags
`-literals -tiny -seed=random`:

- `-literals`: obfuscates string literals in the binary (including the PEM key)
- `-tiny`: strips debug info and symbol tables
- `-seed=random`: randomizes obfuscation per build, so two builds of the same source
  produce different binaries

---

## 2. License File Format and Contents

License files have the `.lic` extension and are standard JSON files.

### 2.1 Envelope Structure

```json
{
  "alg": "ES256",
  "payload": "<base64url-encoded-JSON-string>",
  "sig": "<base64url-encoded-ECDSA-DER-signature>"
}
```

| Field     | Description |
|-----------|-------------|
| `alg`     | Always `"ES256"`. Any other value is rejected. |
| `payload` | The license payload, encoded as base64url (no padding). The underlying data is a JSON object (see below). |
| `sig`     | ECDSA-SHA256 signature in DER format, base64url-encoded (no padding). |

**Critical detail:** The signature is computed over the **raw base64url payload
string bytes** — not over the decoded JSON bytes. This means:

```
signature = ECDSA_SHA256_Sign(orgPrivateKey, bytes("eyJleH..."))
```

This matches the Python backend which signs `base64url_encode(canonical_json(payload))`
as a string.

### 2.2 Decoded Payload (Common Fields)

When you base64url-decode the `payload` field, you get:

```json
{
  "v": 1,
  "license_key": "550e8400-e29b-41d4-a716-446655440000",
  "org_id": "a1b2c3d4-...",
  "software_id": "f5e6d7c8-...",
  "license_type": "STANDARD",
  "issue_date": "2026-01-15",
  "expiry_date": "2027-01-15",
  "max_machines": 5,
  "features": {
    "tier": "enterprise",
    "max_users": 100,
    "module_crypto": true,
    "module_analytics": false
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `v` | `int` | Schema version. Must be `1`. |
| `license_key` | `string` | Unique identifier for this license (UUID). |
| `org_id` | `string` | The organization this license belongs to. |
| `software_id` | `string` | The software product this license authorizes. |
| `license_type` | `string` | Either `"STANDARD"` or `"HARDWARE_BOUND"`. |
| `issue_date` | `string` | Date the license becomes active (`YYYY-MM-DD`). License will not work before this date ("dormancy check"). |
| `expiry_date` | `string` | Date the license expires (`YYYY-MM-DD`). License will not work after this date. |
| `max_machines` | `int` | Maximum number of machines that can be activated with this license. Must be >= 1. |
| `features` | `map[string]any` | Arbitrary key-value map of feature flags. This is what your software reads via IPC to decide what functionality to enable. |

### 2.3 STANDARD License — Additional Fields

```json
{
  "server_url": "https://drm.example.com",
  "heartbeat_interval_minutes": 60,
  "heartbeat_grace_period_days": 7
}
```

| Field | Type | Description |
|-------|------|-------------|
| `server_url` | `string` | Full URL of the DRM backend. Used for activation and heartbeat. |
| `heartbeat_interval_minutes` | `int` | How often (in minutes) sentinel sends a heartbeat to the server. Must be > 0. |
| `heartbeat_grace_period_days` | `int` | Total offline grace period in days. Converted to seconds internally: `days * 86400`. Must be > 0. |

STANDARD licenses must NOT have `hardware_fingerprint` set.

### 2.4 HARDWARE_BOUND License — Additional Fields

```json
{
  "hardware_fingerprint": "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `hardware_fingerprint` | `string` | SHA-256 hex digest of `cpuSerial + diskSerial + machineID` collected from the target machine. Must match the machine's actual fingerprint. |

HARDWARE_BOUND licenses must NOT have `heartbeat_interval_minutes` or
`heartbeat_grace_period_days` set. They also don't need `server_url` (no server
communication occurs).

### 2.5 Validation Rules

The following validations are performed when loading a license:

1. JSON must parse correctly
2. `alg` must be `"ES256"`
3. Signature must verify against the embedded org public key
4. Payload must base64url-decode to valid JSON
5. `v` must be `1`
6. `license_key`, `org_id`, `software_id` must all be non-empty
7. `license_type` must be `"STANDARD"` or `"HARDWARE_BOUND"`
8. `max_machines` must be >= 1
9. `issue_date` and `expiry_date` must be valid `YYYY-MM-DD` dates
10. Today (UTC) must be >= `issue_date` (dormancy check)
11. Today (UTC) must be <= `expiry_date` (expiry check)
12. Type-specific field presence and absence rules (see above)

---

## 3. Startup Sequence

The sentinel client is invoked from the command line:

```bash
./sentinel --license /path/to/license.lic --software /path/to/your-binary
```

Both flags are **required**. There are no other flags (the server URL, heartbeat
interval, etc. all come from the license file).

### 3.1 Step-by-Step Startup

1. **Cobra CLI parses flags** — extracts `--license` and `--software` paths
2. **Embedded key validation** — checks that `orgPublicKeyPEM` is non-empty, unescapes
   `\n` sequences, parses it as an EC P-256 public key
3. **Config validation** — checks that both file paths exist on disk via `os.Stat()`
4. **Signal handler setup** — installs handlers for `SIGINT` and `SIGTERM`. When
   either is received, a context cancellation propagates to all goroutines
5. **License load and verify** — reads the `.lic` file, verifies ECDSA signature,
   decodes and validates the payload
6. **Flow dispatch** — based on `license_type`, delegates to either:
   - `runStandard()` — online license with server heartbeats
   - `runHardwareBound()` — offline hardware-locked license

---

## 4. Startup Checks

### 4.1 STANDARD License Startup Checks

The STANDARD flow performs these checks in order:

#### 4.1.1 License Verification
- ECDSA signature on the `.lic` file verified against the embedded org public key
- Payload decoded and all fields validated (see [Section 2.5](#25-validation-rules))
- Dormancy check: `issue_date` must be <= today (UTC)
- Expiry check: `expiry_date` must be >= today (UTC)

#### 4.1.2 Keystore Initialization
- Gets the machine's stable OS-level machine ID via `hardware.GetMachineID()`:
  - **Linux**: reads `/etc/machine-id`
  - **macOS**: runs `ioreg -rd1 -c IOPlatformExpertDevice` and extracts `IOPlatformUUID`
  - **Windows**: reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` from the registry
- Derives the vault encryption key: `SHA256("sentinel-drm-keystore:" + machineID)`
  - This means the keystore file is **cryptographically bound to the machine** — copying
    it to another machine produces gibberish
- Opens or creates the keystore file at:
  - Linux: `~/.local/share/sentinel-drm/keystore.enc`
  - macOS: `~/Library/Application Support/sentinel-drm/keystore.enc`
  - Windows: `%APPDATA%\sentinel-drm\keystore.enc`

The keystore is a JSON file where each entry is individually encrypted with
AES-256-GCM. On-disk format per entry: `base64(nonce_12_bytes || ciphertext)`.
Writes are atomic (write to `.tmp`, then `rename`).

#### 4.1.3 Machine EC Keypair
- Attempts to retrieve the key `"machine-private-key"` from the keystore
- **First run**: generates a new EC P-256 keypair, stores the private key (PKCS8 PEM)
  in the keystore
- **Subsequent runs**: loads the existing private key from the keystore, protects it
  in locked memory using `memguard.NewBufferFromBytes()` to prevent it from being
  swapped to disk
- Extracts the public key PEM (needed for activation)

#### 4.1.4 Encrypted State Load
- The state manager retrieves or generates a 32-byte AES-256-GCM key from the keystore
  (key name: `"state-encryption-key"`)
- Attempts to load the encrypted state file from:
  - Linux: `~/.local/share/sentinel-drm/state.enc`
  - macOS: `~/Library/Application Support/sentinel-drm/state.enc`
  - Windows: `%APPDATA%\sentinel-drm\state.enc`
- On-disk format: `nonce_12_bytes || AES-256-GCM_ciphertext`
- **First run**: state file doesn't exist — creates new state:
  ```json
  {
    "machine_id": "<new-uuid-v4>",
    "activated": false,
    "license_key": "<from-license-file>",
    "last_heartbeat_success": 0,
    "grace_remaining_seconds": <heartbeat_grace_period_days * 86400>,
    "grace_exhausted": false
  }
  ```
- **Subsequent runs**: decrypts and loads existing state

#### 4.1.5 License Key Change Detection
- Compares `state.license_key` with the license file's `license_key`
- If different (user switched to a new license file): resets `activated` to false,
  updates the license key, resets grace period to full, clears `grace_exhausted`

#### 4.1.6 Activation (if not yet activated)
- POSTs to `{server_url}/api/v1/drm/activate/` with:
  - `license_key`, `machine_id`, `machine_public_key_pem`, `platform`, `software_version`
- The server registers this machine, stores the machine's public key for future
  request verification
- On success: sets `activated = true`, records `last_heartbeat_success = now()`

#### 4.1.7 Mandatory Startup Heartbeat
Every STANDARD startup **must** contact the server. This prevents an attacker from
endlessly restarting the client to abuse the grace period:

- POSTs to `{server_url}/api/v1/drm/heartbeat/`
- **If server responds successfully**: processes the response (see [Section 11](#11-data-exchanged-with-the-backend-server))
- **If connection error** (network down, DNS failure, timeout):
  - If `grace_exhausted == true` → **refuses to start** ("server unreachable and
    grace period exhausted")
  - If `grace_remaining_seconds <= 0` → sets `grace_exhausted = true`, **refuses to start**
  - Otherwise → logs a warning, continues under grace period
- **If server error** (HTTP 4xx/5xx with a body like `{"error": "license revoked"}`):
  → **refuses to start** immediately. Server errors are not connection failures, they
  are definitive rejections.

### 4.2 HARDWARE_BOUND License Startup Checks

The HARDWARE_BOUND flow is simpler — no server communication at all:

#### 4.2.1 License Verification
Same as STANDARD (signature, payload, dormancy, expiry).

#### 4.2.2 Hardware Fingerprint Collection
Gathers three hardware identifiers:

| Component | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| CPU Serial | `/sys/class/dmi/id/product_uuid` (x86) or `/proc/cpuinfo` Serial field (ARM) | `ioreg` → `IOPlatformSerialNumber` | PowerShell `Get-CimInstance Win32_Processor` → `ProcessorId` |
| Disk Serial | `findmnt -n -o SOURCE /` → `/sys/block/<dev>/serial` | `diskutil info /` → `Volume UUID` or `Disk / Partition UUID` | PowerShell `Get-CimInstance Win32_DiskDrive` → `SerialNumber` |
| Machine ID | `/etc/machine-id` | `ioreg` → `IOPlatformUUID` | Registry `HKLM\...\Cryptography\MachineGuid` |

The fingerprint is computed as:
```
SHA256_Hex(cpuSerial + diskSerial + machineID)
```

This is a simple string concatenation (no separator), then SHA-256 hex-encoded.

#### 4.2.3 Fingerprint Comparison
- Compares the computed fingerprint with `license.hardware_fingerprint`
- **Exact string match required.** Any difference → `"hardware fingerprint mismatch:
  this license is not valid for this machine"`

No keystore, state file, activation, or heartbeat is needed.

---

## 5. How the Software Binary is Launched

### 5.1 Launch Mechanism

Your software binary is launched as a **child process** of the sentinel client:

```go
cmd := exec.Command(binaryPath)        // no arguments passed to the binary
cmd.Env = append(os.Environ(),          // inherits all parent env vars
    "SENTINEL_IPC_SOCKET=" + ipcSocketPath,  // plus one new one
)
cmd.Stdout = os.Stdout                  // child stdout → sentinel stdout
cmd.Stderr = os.Stderr                  // child stderr → sentinel stderr
cmd.Start()
```

### 5.2 Key Points

- **No command-line arguments** are passed to your binary. Your binary is invoked as
  just `./your-binary` with zero args.
- **Full environment inherited.** Your binary receives all environment variables that
  the sentinel process has, plus the additional `SENTINEL_IPC_SOCKET` variable.
- **Stdout/stderr are shared.** Anything your binary prints to stdout or stderr will
  appear in the sentinel process's output. This is how users see your software's
  console output.
- **Stdin is NOT connected.** Your software does not have access to interactive stdin
  through sentinel.

### 5.3 The `SENTINEL_IPC_SOCKET` Environment Variable

This is the **single integration point** between sentinel and your software. It
contains the path to the IPC endpoint:

| Platform | Format | Example |
|----------|--------|---------|
| Linux    | Unix domain socket path | `/tmp/sentinel-550e8400-e29b-41d4-a716-446655440000.sock` |
| macOS    | Unix domain socket path | `/tmp/sentinel-a3f8b2c1d4e5.sock` |
| Windows  | Named pipe path | `\\.\pipe\sentinel-550e8400-e29b-41d4-a716-446655440000` |

For STANDARD licenses, the ID in the path is the `machine_id` UUID from the encrypted
state. For HARDWARE_BOUND licenses, it is the hardware fingerprint hash.

### 5.4 Process Lifecycle

- Sentinel **monitors the child process** via a goroutine that calls `cmd.Wait()`
  and closes a channel (`exited`) when the process exits.
- If sentinel needs to shut down (signal received, heartbeat failure, grace exhausted,
  license revoked, etc.), it stops the child:
  - **Unix (Linux/macOS)**: sends `SIGTERM`, waits up to 10 seconds for clean
    shutdown, then sends `SIGKILL` if the process is still running
  - **Windows**: calls `Process.Kill()` directly (Windows does not support SIGTERM)
- If the **child process exits on its own** (normal exit or crash), sentinel performs
  cleanup (saves state, closes IPC server) and then exits with the child's exit code.

---

## 6. IPC Protocol — Communication Between Sentinel and Your Software

### 6.1 Transport Layer

| Platform | Transport | Library/Syscall |
|----------|-----------|-----------------|
| Linux    | Unix domain socket (`AF_UNIX`, `SOCK_STREAM`) | Go `net.Listen("unix", path)` |
| macOS    | Unix domain socket (`AF_UNIX`, `SOCK_STREAM`) | Go `net.Listen("unix", path)` |
| Windows  | Named pipe | `github.com/Microsoft/go-winio` → `winio.ListenPipe(path, nil)` |

### 6.2 Protocol: JSON-over-Newline

The protocol is extremely simple:

1. Each message is a **single JSON object** followed by a newline character (`\n`)
2. The connection is **bidirectional** — your software sends requests, sentinel
   sends responses
3. The protocol is **synchronous per connection** — send a request, read a response,
   repeat
4. **Multiple concurrent connections are supported** — the IPC server handles each
   connection in its own goroutine

### 6.3 Request Format

Your software sends:

```json
{"method": "<method_name>"}\n
```

The only field is `method`. There are no parameters, no request IDs, no authentication.

### 6.4 Available Methods

| Method | Description | Response Fields |
|--------|-------------|-----------------|
| `get_license` | Returns full license metadata | `status`, `license` |
| `get_features` | Returns just the features map | `status`, `features` |
| `health` | Checks if sentinel is alive | `status` |

### 6.5 Response Format

**Success responses:**

```json
{"status": "ok", "license": {...}}\n
{"status": "ok", "features": {...}}\n
{"status": "ok"}\n
```

**Error responses:**

```json
{"status": "error", "error": "description of what went wrong"}\n
```

### 6.6 `get_license` — Full Response

```json
{
  "status": "ok",
  "license": {
    "license_key": "550e8400-e29b-41d4-a716-446655440000",
    "license_type": "STANDARD",
    "expiry_date": "2027-01-15",
    "features": {
      "tier": "enterprise",
      "max_users": 100,
      "module_crypto": true,
      "module_analytics": false
    },
    "org_id": "a1b2c3d4-...",
    "software_id": "f5e6d7c8-..."
  }
}
```

The `LicenseInfo` struct exposed over IPC contains:

| Field | Type | Description |
|-------|------|-------------|
| `license_key` | `string` | The license's unique identifier |
| `license_type` | `string` | `"STANDARD"` or `"HARDWARE_BOUND"` |
| `expiry_date` | `string` | Expiry in `YYYY-MM-DD` format |
| `features` | `object` | Arbitrary key-value feature flags (the same map from the license payload) |
| `org_id` | `string` | Organization identifier |
| `software_id` | `string` | Software product identifier |

### 6.7 `get_features` — Full Response

```json
{
  "status": "ok",
  "features": {
    "tier": "enterprise",
    "max_users": 100,
    "module_crypto": true,
    "module_analytics": false
  }
}
```

This is a convenience method that returns just the `features` map without the rest
of the license metadata.

### 6.8 `health` — Full Response

```json
{"status": "ok"}
```

A simple liveness check. If the connection is alive and sentinel responds, the
client is healthy.

### 6.9 Unknown Methods

```json
{"status": "error", "error": "unknown method: foo"}
```

### 6.10 Malformed Requests

If the sent JSON is not parseable:

```json
{"status": "error", "error": "malformed request"}
```

---

## 7. Complete Communication Flow Diagrams

### 7.1 STANDARD License — Full Lifecycle

```
User runs: ./sentinel --license app.lic --software ./myapp

 ┌─────────────────────┐
 │  1. Parse CLI flags  │
 │  2. Validate org key │
 │  3. Validate paths   │
 └─────────┬───────────┘
           │
 ┌─────────▼───────────────┐
 │  4. Load & verify .lic  │
 │     - Verify ECDSA sig  │
 │     - Decode payload    │
 │     - Check dormancy    │
 │     - Check expiry      │
 └─────────┬───────────────┘
           │
 ┌─────────▼───────────────────┐
 │  5. Init keystore           │
 │     - GetMachineID()        │
 │     - DeriveVaultKey()      │
 │     - Open keystore.enc     │
 └─────────┬───────────────────┘
           │
 ┌─────────▼───────────────────┐
 │  6. Load/generate machine   │
 │     EC P-256 keypair        │
 └─────────┬───────────────────┘
           │
 ┌─────────▼───────────────────┐
 │  7. Load/create state.enc   │
 └─────────┬───────────────────┘
           │
 ┌─────────▼───────────────────┐
 │  8. License key change?     │
 │     → Reset activation      │
 └─────────┬───────────────────┘
           │
 ┌─────────▼────────────────────────────┐
 │  9. Activate (if not yet activated)  │
 │     POST /api/v1/drm/activate/       │
 │     → Server stores machine pub key  │
 └─────────┬────────────────────────────┘
           │
 ┌─────────▼────────────────────────────┐
 │  10. Mandatory startup heartbeat     │
 │      POST /api/v1/drm/heartbeat/     │
 │      → Grace logic on failure        │
 └─────────┬────────────────────────────┘
           │
 ┌─────────▼────────────────────┐
 │  11. Launch software binary  │
 │      with SENTINEL_IPC_SOCKET│
 └─────────┬────────────────────┘
           │
     ┌─────┼─────────────────────────┐
     │     │                         │
 ┌───▼──┐ ┌▼──────────────┐  ┌──────▼──────────┐
 │ IPC  │ │ Anti-tamper    │  │ Heartbeat loop  │
 │Server│ │ monitor        │  │ (goroutine)     │
 │(goro)│ │ (goroutine)    │  │                 │
 └──┬───┘ └───────────────┘  └─────────────────┘
    │
    │  ← Your software connects here
    │     and sends get_license, get_features, health
    │
 ┌──▼──────────────────────────────────────┐
 │  12. Wait for:                          │
 │      - Software process exit            │
 │      - SIGINT / SIGTERM                 │
 │      - Fatal heartbeat failure          │
 │      - Grace period exhaustion          │
 │      - License revocation/expiry        │
 └─────────────────────────────────────────┘
```

### 7.2 HARDWARE_BOUND License — Full Lifecycle

```
 ┌─────────────────────┐
 │  1-4. Same as above │
 │  (parse, verify)    │
 └─────────┬───────────┘
           │
 ┌─────────▼───────────────────────┐
 │  5. Collect hardware fingerprint│
 │     CPU serial + Disk UUID +    │
 │     Machine ID → SHA256 hex     │
 └─────────┬───────────────────────┘
           │
 ┌─────────▼───────────────────────┐
 │  6. Compare with license        │
 │     fingerprint — must match    │
 └─────────┬───────────────────────┘
           │
 ┌─────────▼────────────────────┐
 │  7. Launch software binary   │
 │     with SENTINEL_IPC_SOCKET │
 └─────────┬────────────────────┘
           │
     ┌─────┼──────────────┐
     │     │              │
 ┌───▼──┐ ┌▼──────────────┐
 │ IPC  │ │ Anti-tamper    │
 │Server│ │ monitor        │
 └──┬───┘ └───────────────┘
    │
 ┌──▼──────────────────────────┐
 │  8. Wait for:               │
 │     - Software process exit │
 │     - SIGINT / SIGTERM      │
 │  (no heartbeat — fully      │
 │   offline operation)        │
 └─────────────────────────────┘
```

### 7.3 Your Software's Perspective

```
 ┌─────────────────────────────────────────────────┐
 │                YOUR SOFTWARE                     │
 ├─────────────────────────────────────────────────┤
 │                                                  │
 │  1. Read env var SENTINEL_IPC_SOCKET             │
 │     └─ If not set → not launched by sentinel,    │
 │        refuse to run or run in demo mode         │
 │                                                  │
 │  2. Connect to the socket (TCP-like stream)      │
 │     └─ Unix domain socket on Linux/macOS         │
 │     └─ Named pipe on Windows                     │
 │                                                  │
 │  3. Send: {"method":"get_license"}\n             │
 │     Read: {"status":"ok","license":{...}}\n      │
 │     └─ Extract license_type, expiry_date,        │
 │        org_id, software_id                       │
 │                                                  │
 │  4. Send: {"method":"get_features"}\n            │
 │     Read: {"status":"ok","features":{...}}\n     │
 │     └─ Use features to enable/disable modules    │
 │     └─ e.g. features["tier"] == "enterprise"     │
 │     └─ e.g. features["max_users"] == 100         │
 │                                                  │
 │  5. Run your application logic normally           │
 │                                                  │
 │  6. (Optional) Periodically:                     │
 │     Send: {"method":"health"}\n                  │
 │     Read: {"status":"ok"}\n                      │
 │     └─ If connection drops → sentinel is gone    │
 │        → shut down gracefully                    │
 │                                                  │
 │  7. Handle SIGTERM for clean shutdown             │
 │     └─ Sentinel sends SIGTERM when stopping you  │
 │                                                  │
 └─────────────────────────────────────────────────┘
```

---

## 8. Data Exchanged Between Sentinel and the Software

### 8.1 Software → Sentinel (Requests)

| Message | Purpose | When to Send |
|---------|---------|--------------|
| `{"method":"get_license"}` | Get full license metadata | On startup, to learn license type, expiry, org, software ID |
| `{"method":"get_features"}` | Get feature flags map | On startup, and optionally periodically to re-check features |
| `{"method":"health"}` | Liveness check | Periodically (e.g., every 30-60 seconds) to detect sentinel death |

### 8.2 Sentinel → Software (Responses)

| Response | Contains | Notes |
|----------|----------|-------|
| `get_license` success | `license_key`, `license_type`, `expiry_date`, `features`, `org_id`, `software_id` | Full license metadata |
| `get_features` success | `features` map only | Just the feature flags |
| `health` success | `status: "ok"` only | No payload |
| Any error | `status: "error"`, `error: "..."` | Could indicate degradation |

### 8.3 What is NOT Exchanged

- No private keys, public keys, or any cryptographic material
- No server URLs or backend communication details
- No machine IDs, fingerprints, or hardware information
- No heartbeat status or grace period information
- No session tokens or authentication credentials

The IPC channel is **purely for license metadata delivery**. Your software is
deliberately kept unaware of the DRM enforcement mechanics.

---

## 9. Tamper Detection and Anti-Debug

### 9.1 What is Monitored

The anti-tamper monitor runs as a background goroutine and checks for **debugger
attachment** on the sentinel process itself:

| Platform | Detection Method | What It Detects |
|----------|-----------------|-----------------|
| Linux | Reads `/proc/self/status`, looks for `TracerPid:` line, checks if value != 0 | `ptrace` attach (gdb, strace, ltrace, etc.) |
| macOS | Calls `unix.SysctlKinfoProc("kern.proc.pid", pid)`, checks `Proc.P_flag & 0x800` | `PT_TRACE_ME` / `PT_ATTACH` (lldb, dtrace, etc.) |
| Windows | Calls `kernel32.IsDebuggerPresent()` AND `kernel32.CheckRemoteDebuggerPresent()` | Both local debuggers (WinDbg, x64dbg) and remote debuggers |

### 9.2 Check Timing

- **First check**: immediately at startup, before entering the loop
- **Subsequent checks**: every 5-10 seconds (randomized interval via `rand.Intn(6) + 5`)
- The randomization prevents attackers from predicting the exact check timing and
  detaching the debugger just before the check fires

### 9.3 Binary Checksum Verification

The `process.VerifyBinaryChecksum()` function exists and can compute SHA-256 of
the software binary file, comparing it against an expected checksum. This is
available for future use when the license payload includes a software checksum field.

---

## 10. Server Communication and Mutual Signing (HTTPS-Compromised Model)

The design assumes **HTTPS may be compromised** (e.g., corporate MITM proxies,
compromised CAs). All communication is protected by an additional ECDSA signing
layer on top of HTTP.

### 10.1 Request Signing (Client → Server)

Every HTTP request to the DRM backend is a `POST` with a JSON body and four
custom headers:

```http
POST /api/v1/drm/heartbeat/ HTTP/1.1
Content-Type: application/json
X-Sentinel-Machine-Id: 550e8400-e29b-41d4-a716-446655440000
X-Sentinel-Timestamp: 1709136000
X-Sentinel-Nonce: 6ba7b810-9dad-11d1-80b4-00c04fd430c8
X-Sentinel-Signature: MEUCIQDk...

{"license_key":"...","machine_id":"...","software_version":"1.0.0"}
```

The **signing string** is constructed as:

```
POST\n/api/v1/drm/heartbeat/\n1709136000\n6ba7b810-9dad-11d1-80b4-00c04fd430c8\n<sha256-hex-of-request-body>
```

Format: `{METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256_HEX(BODY)}`

This string is then signed with ECDSA-SHA256 using the **machine's EC private key**:

```
signature = ECDSA_SHA256_Sign(machinePrivateKey, bytes(signingString))
```

The signature is base64url-encoded (no padding) and set as the
`X-Sentinel-Signature` header.

The server verifies this signature using the machine's public key (which it received
during activation).

### 10.2 Response Verification (Server → Client)

Every server response body is an envelope:

```json
{
  "payload": "eyJzdGF0dXMiOiJBQ1RJVkUiLC...",
  "sig": "MEUCIQDrY2..."
}
```

| Field | Description |
|-------|-------------|
| `payload` | Base64url-encoded canonical JSON of the response data |
| `sig` | Base64url-encoded ECDSA-SHA256 DER signature |

The client verifies the signature:

```
signature_valid = ECDSA_SHA256_Verify(orgPublicKey, bytes(payload_string), decode(sig))
```

**Critical:** The signature is over the raw base64url payload **string** (e.g.,
`"eyJzdGF0dXMi..."` as bytes), NOT the decoded JSON bytes.

### 10.3 Nonce Reflection (Anti-Replay)

Every request includes a random UUID nonce in `X-Sentinel-Nonce`. The server MUST
include this same nonce in its response payload as the `request_nonce` field. The
client verifies that `response.request_nonce == request.nonce`.

This prevents replay attacks: an attacker cannot capture a valid server response
and replay it for a different request, because the nonce won't match.

### 10.4 What This Protects Against

| Threat | Protection |
|--------|------------|
| MITM reading traffic | HTTPS (but assumed compromised) |
| MITM forging server responses | Org private key needed to sign responses — attacker doesn't have it |
| MITM forging client requests | Machine private key needed to sign requests — attacker doesn't have it |
| Replay of old server responses | Nonce mismatch — each request has a unique nonce |
| Replay of old client requests | Timestamp + nonce in signing string |
| Stolen machine talking to wrong server | Org public key must match server's private key |

### 10.5 HTTP Client Configuration

- Timeout: 30 seconds per request
- Response body cap: 1 MB (prevents memory exhaustion from malicious large responses)

---

## 11. Data Exchanged With the Backend Server

### 11.1 Activation — `POST /api/v1/drm/activate/`

**When:** First startup for a STANDARD license, or after a license key change.

**Request body:**

```json
{
  "license_key": "550e8400-e29b-41d4-a716-446655440000",
  "machine_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "machine_public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n",
  "platform": "LINUX_AMD64",
  "software_version": "1.0.0"
}
```

| Field | Description |
|-------|-------------|
| `license_key` | From the license file |
| `machine_id` | UUID v4 generated at first run, persisted in encrypted state |
| `machine_public_key_pem` | The machine's EC P-256 public key in PEM format. The server stores this to verify future requests from this machine. |
| `platform` | One of: `LINUX_AMD64`, `LINUX_ARM64`, `DARWIN_ARM64`, `WINDOWS_AMD64`, `WINDOWS_ARM64` |
| `software_version` | From the build-time ldflags version string |

**Response payload (after decoding and verification):**

```json
{
  "status": "ACTIVE",
  "machine_id": "a1b2c3d4-...",
  "license_key": "550e8400-...",
  "expiry_date": "2027-01-15",
  "heartbeat_interval_minutes": 60,
  "heartbeat_grace_period_days": 7,
  "features": {"tier": "enterprise", "max_users": 100},
  "request_nonce": "6ba7b810-...",
  "responded_at": "2026-02-28T12:00:00Z"
}
```

### 11.2 Heartbeat — `POST /api/v1/drm/heartbeat/`

**When:** At every startup (mandatory), then periodically every
`heartbeat_interval_minutes` minutes.

**Request body:**

```json
{
  "license_key": "550e8400-...",
  "machine_id": "a1b2c3d4-...",
  "software_version": "1.0.0"
}
```

**Response payload:**

```json
{
  "status": "ACTIVE",
  "machine_id": "a1b2c3d4-...",
  "license_key": "550e8400-...",
  "expiry_date": "2027-01-15",
  "decommission_pending": false,
  "request_nonce": "...",
  "responded_at": "..."
}
```

**Possible `status` values and their effect:**

| Status | Meaning | Sentinel Action |
|--------|---------|-----------------|
| `ACTIVE` | License is valid and active | Continue running normally |
| `DECOMMISSION_PENDING` | Admin requested this machine be removed | Send decommission ack, delete state file, shut down |
| `REVOKED` | License has been revoked | Shut down immediately |
| `EXPIRED` | License has expired | Shut down immediately |
| `SUSPENDED` | License is temporarily suspended | Shut down immediately |

### 11.3 Decommission Acknowledgment — `POST /api/v1/drm/decommission-ack/`

**When:** After receiving `status: "DECOMMISSION_PENDING"` in a heartbeat response.

**Request body:**

```json
{
  "license_key": "550e8400-...",
  "machine_id": "a1b2c3d4-..."
}
```

**Response payload:**

```json
{
  "status": "ok",
  "machine_id": "a1b2c3d4-...",
  "license_key": "550e8400-...",
  "request_nonce": "...",
  "responded_at": "..."
}
```

After sending this, sentinel deletes its local state file and shuts down. The
machine slot is freed on the server, allowing a new machine to activate.

### 11.4 Grace Period Mechanics (STANDARD Only)

The grace period allows the software to keep running temporarily when the server
is unreachable:

- **Total quota**: `heartbeat_grace_period_days * 86400` seconds
- **On each missed heartbeat** (connection error): `grace_remaining -= heartbeat_interval_minutes * 60`
- **On successful heartbeat**: `last_heartbeat_success` is updated, but **remaining grace is NOT reset**. The quota only decreases, never refills.
- **Server errors** (HTTP 4xx/5xx): do NOT consume grace. These indicate the server
  is reachable but rejected the request — sentinel logs the error and retries next
  interval.
- **When grace reaches 0**: `grace_exhausted` flag is set to `true`. From this point,
  the very next connection error (even on startup) will cause an immediate shutdown.
- **Grace exhaustion is permanent** for a given license key. Switching to a new
  license file resets the grace period.

---

## 12. Anti-Tamper Degradation — How It Affects Sentinel and Your Software

### 12.1 Degradation Stages

When a debugger is detected, sentinel does **not** immediately terminate. Instead,
it progressively degrades over approximately 10 minutes to make detection ambiguous
and harder to reverse-engineer:

| Stage | Time Window | Sentinel-Side Effects | IPC Effects on Your Software |
|-------|-------------|----------------------|------------------------------|
| **StageNormal** | No detection | Normal operation | All responses correct |
| **StageWarnings** | 0 – 2 min after detection | Cryptic warning messages printed to stderr every 15-30 seconds | **No IPC effect.** Responses are completely normal. |
| **StageErrors** | 2 – 5 min after detection | Escalated error messages to stderr | **~30% of IPC requests return fake errors.** `get_license` returns `"license validation failed"`. `get_features` returns empty `{}`. |
| **StageSlowdown** | 5 – 10 min after detection | Memory allocation (50 MB in 1 MB chunks) + 2 CPU-burning goroutines | Same IPC degradation as StageErrors, plus **sentinel becomes sluggish** due to resource pressure. IPC response times increase. |
| **StageCrash** | 10+ min after detection | Random 0-60 second delay, then `os.Exit(137)` | **Sentinel dies.** Your software loses the IPC socket connection. Exit code 137 mimics SIGKILL/OOM to obscure the true cause. |

### 12.2 Timing Jitter

Each stage transition has **±30 seconds of random jitter** applied. This means:

- StageWarnings → StageErrors: happens somewhere between 1:30 and 2:30 after detection
- StageErrors → StageSlowdown: happens somewhere between 4:30 and 5:30
- StageSlowdown → StageCrash: happens somewhere between 9:30 and 10:30

This prevents attackers from fingerprinting exact transition times to identify the
anti-tamper mechanism.

### 12.3 Warning Messages (Printed to Stderr)

During **StageWarnings**, messages like:
```
WARNING: memory integrity check: segment checksum recalculating...
WARN: unexpected TLB flush in secure region
caution: runtime verification handshake delayed
NOTE: entropy pool reseeding (source: hardware)
WARN: secure context migration pending
```

During **StageErrors** and beyond, messages escalate to:
```
ERROR: ENOMEM in secure allocator (pool exhausted)
error: EACCES verifying runtime signature (retrying...)
FATAL: page fault in protected region 0x7fff...
error: secure channel handshake timeout (attempt 3/5)
```

These are deliberately designed to look like genuine system/runtime errors, making
it harder for an attacker to distinguish anti-tamper activity from real problems.

### 12.4 Resource Pressure (StageSlowdown)

When StageSlowdown is entered:

- **Memory pressure**: a goroutine allocates 50 one-megabyte chunks (50 MB total)
  filled with random data, with 500-1500ms delays between chunks. The memory is
  intentionally leaked.
- **CPU pressure**: 2 goroutines run tight loops computing SHA-256 hashes of 4 KB
  buffers, with 0-100ms random sleeps between iterations.

### 12.5 Crash Behavior (StageCrash)

- Waits a random 0-60 seconds
- Prints one of:
  ```
  FATAL: out of memory in secure allocator
  PANIC: stack corruption detected in runtime verifier
  FATAL: unable to recover from page fault in protected region
  ```
- Calls `os.Exit(137)` — exit code 137 = 128 + 9 = SIGKILL, which looks like the
  OS killed the process due to OOM

---

## 13. How Degradation Commands Reach Your Software

Sentinel does **not** send an explicit "degrade now" command to your software. The
degradation is entirely **passive and observable through IPC response quality**:

### 13.1 Normal Operation
```
Software: {"method":"get_features"}
Sentinel: {"status":"ok","features":{"tier":"enterprise","max_users":100}}
```

### 13.2 During StageErrors / StageSlowdown
```
Software: {"method":"get_features"}
Sentinel: {"status":"ok","features":{}}                         ← empty features
         OR
Sentinel: {"status":"error","error":"broken pipe"}              ← fake error (~30%)
         OR
Sentinel: {"status":"error","error":"resource temporarily unavailable"}
         OR
Sentinel: {"status":"error","error":"no such file or directory"}
         OR
Sentinel: {"status":"error","error":"connection reset by peer"}
```

For `get_license` specifically:
```
Sentinel: {"status":"error","error":"license validation failed"}
```

### 13.3 During StageCrash

The IPC connection simply drops (EOF / broken pipe) because sentinel has exited.

### 13.4 What Your Software Should Do

1. **Always check `status` in every IPC response.** If it's `"error"`, do not
   trust any data in the response.
2. **If `get_features` returns an empty map `{}`**, treat it as if no features
   are licensed — disable premium functionality.
3. **If the IPC connection drops entirely** (read returns EOF, or connect fails),
   assume sentinel is gone — shut down or enter a restricted/demo mode.
4. **Do not try to distinguish anti-tamper errors from real errors.** That is
   intentional by design. If IPC is unreliable, your software should degrade
   its own functionality or shut down.

---

## 14. Software Integration Checklist

### 14.1 Mandatory Requirements

#### Read the IPC socket path

```python
# Python example
import os
socket_path = os.environ.get("SENTINEL_IPC_SOCKET")
if not socket_path:
    print("ERROR: This software must be launched by the Sentinel DRM client.", file=sys.stderr)
    sys.exit(1)
```

```go
// Go example
socketPath := os.Getenv("SENTINEL_IPC_SOCKET")
if socketPath == "" {
    log.Fatal("This software must be launched by the Sentinel DRM client.")
}
```

```c
// C example
const char *socket_path = getenv("SENTINEL_IPC_SOCKET");
if (!socket_path) {
    fprintf(stderr, "This software must be launched by the Sentinel DRM client.\n");
    exit(1);
}
```

#### Connect to the IPC socket

**Unix (Linux/macOS):**
```python
import socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(socket_path)
```

**Windows (Named Pipe):**
```python
# Using pywin32 or ctypes
handle = win32file.CreateFile(
    socket_path,
    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
    0, None,
    win32file.OPEN_EXISTING,
    0, None
)
```

**Go (cross-platform):**
```go
import "net"

// On Unix:
conn, err := net.Dial("unix", socketPath)

// On Windows (with go-winio):
conn, err := winio.DialPipe(socketPath, nil)
```

#### Send JSON requests and read JSON responses

```python
import json

def ipc_call(sock, method):
    request = json.dumps({"method": method}) + "\n"
    sock.sendall(request.encode("utf-8"))

    # Read until newline
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Sentinel IPC connection lost")
        data += chunk
        if b"\n" in data:
            line, _ = data.split(b"\n", 1)
            return json.loads(line)
```

```go
import (
    "bufio"
    "encoding/json"
    "net"
)

func ipcCall(conn net.Conn, method string) (map[string]any, error) {
    req, _ := json.Marshal(map[string]string{"method": method})
    req = append(req, '\n')
    if _, err := conn.Write(req); err != nil {
        return nil, err
    }

    scanner := bufio.NewScanner(conn)
    if !scanner.Scan() {
        return nil, fmt.Errorf("sentinel IPC connection lost")
    }

    var resp map[string]any
    if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
        return nil, err
    }
    return resp, nil
}
```

#### Fetch license and features on startup

```python
# Get full license info
license_resp = ipc_call(sock, "get_license")
if license_resp["status"] != "ok":
    print(f"License error: {license_resp.get('error')}", file=sys.stderr)
    sys.exit(1)

license_info = license_resp["license"]
print(f"License type: {license_info['license_type']}")
print(f"Expiry: {license_info['expiry_date']}")
print(f"Org: {license_info['org_id']}")

# Get features
features_resp = ipc_call(sock, "get_features")
if features_resp["status"] != "ok":
    print(f"Features error: {features_resp.get('error')}", file=sys.stderr)
    sys.exit(1)

features = features_resp["features"]

# Use features to gate functionality
if features.get("tier") == "enterprise":
    enable_enterprise_features()
if features.get("max_users"):
    set_user_limit(features["max_users"])
if features.get("module_crypto"):
    enable_crypto_module()
```

#### Handle SIGTERM for clean shutdown

```python
import signal, sys

def handle_sigterm(signum, frame):
    print("Received SIGTERM, shutting down gracefully...")
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)
```

```go
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
go func() {
    <-sigCh
    cleanup()
    os.Exit(0)
}()
```

### 14.2 Recommended Practices

#### Periodic health checks

Run a background thread/goroutine that sends `health` every 30-60 seconds:

```python
import threading, time

def health_check_loop(sock):
    while True:
        time.sleep(30)
        try:
            resp = ipc_call(sock, "health")
            if resp["status"] != "ok":
                print("Sentinel health check failed", file=sys.stderr)
                trigger_shutdown()
        except (ConnectionError, BrokenPipeError):
            print("Lost connection to Sentinel", file=sys.stderr)
            trigger_shutdown()

threading.Thread(target=health_check_loop, args=(sock,), daemon=True).start()
```

#### Handle IPC errors gracefully

```python
def safe_get_features(sock):
    try:
        resp = ipc_call(sock, "get_features")
        if resp["status"] == "ok" and resp.get("features"):
            return resp["features"]
        # Empty features or error status → degraded mode
        return {}
    except Exception:
        # Connection lost → sentinel is dead
        return None  # caller should shut down
```

#### Connection retry on startup

The IPC server starts just before your binary is launched, but there may be a
brief race condition. Retry a few times:

```python
import time, socket as sock_module

def connect_with_retry(socket_path, max_retries=5, delay=0.5):
    for attempt in range(max_retries):
        try:
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_STREAM)
            s.connect(socket_path)
            return s
        except (ConnectionRefusedError, FileNotFoundError):
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise
```

### 14.3 What You Do NOT Need To Do

| Concern | Handled By |
|---------|------------|
| Parsing the .lic file | Sentinel |
| Verifying license signatures | Sentinel |
| Checking license expiry | Sentinel |
| Communicating with the DRM backend | Sentinel |
| Sending heartbeats | Sentinel |
| Managing grace periods | Sentinel |
| Hardware fingerprinting | Sentinel |
| Machine keypair management | Sentinel |
| Encrypting/decrypting state | Sentinel |
| Anti-tamper / debugger detection | Sentinel |
| Encrypting the IPC channel | Not needed (local socket — only same-machine processes can connect) |
| Embedding any keys in your binary | Not needed |
| Knowing the server URL | Not needed |

### 14.4 Data Types Reference for the `features` Map

The `features` map uses JSON types. Your software should handle:

| JSON Type | Example | Go Type | Python Type |
|-----------|---------|---------|-------------|
| `string` | `"tier": "enterprise"` | `string` | `str` |
| `number` (integer) | `"max_users": 100` | `float64` (JSON default in Go) | `int` or `float` |
| `number` (float) | `"rate_limit": 1.5` | `float64` | `float` |
| `boolean` | `"module_crypto": true` | `bool` | `bool` |
| `null` | `"deprecated_field": null` | `nil` | `None` |
| `array` | `"allowed_ips": ["10.0.0.0/8"]` | `[]any` | `list` |
| `object` | `"limits": {"cpu": 4}` | `map[string]any` | `dict` |

The structure of the features map is entirely defined by you (the software vendor)
when creating licenses through the Sentinel DRM backend. Sentinel treats it as an
opaque pass-through.

### 14.5 Platform-Specific Notes

#### Linux
- IPC socket at `/tmp/sentinel-<id>.sock`
- Connect with `AF_UNIX`, `SOCK_STREAM`
- SIGTERM is sent on graceful shutdown

#### macOS
- Same as Linux (Unix domain socket)
- IPC socket at `/tmp/sentinel-<id>.sock`
- SIGTERM is sent on graceful shutdown

#### Windows
- IPC via named pipe at `\\.\pipe\sentinel-<id>`
- Connect with `CreateFile()` (Win32 API) or language-specific named pipe libraries
- No SIGTERM — process is killed directly with `TerminateProcess()`
- Your Windows software should handle abrupt termination gracefully (flush buffers,
  close file handles in `atexit` handlers)

### 14.6 Minimal Complete Integration Example (Python)

```python
#!/usr/bin/env python3
"""Minimal software binary integrated with Sentinel DRM client."""

import json
import os
import signal
import socket
import sys
import time
import threading


def ipc_call(sock, method):
    """Send a JSON-over-newline IPC request and return the parsed response."""
    request = json.dumps({"method": method}) + "\n"
    sock.sendall(request.encode("utf-8"))
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Sentinel IPC connection lost")
        data += chunk
    line = data.split(b"\n", 1)[0]
    return json.loads(line)


def main():
    # --- Step 1: Read the IPC socket path ---
    socket_path = os.environ.get("SENTINEL_IPC_SOCKET")
    if not socket_path:
        print("ERROR: Must be launched by Sentinel DRM client.", file=sys.stderr)
        sys.exit(1)

    # --- Step 2: Connect to the IPC socket ---
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for attempt in range(5):
        try:
            sock.connect(socket_path)
            break
        except (ConnectionRefusedError, FileNotFoundError):
            if attempt == 4:
                print("ERROR: Cannot connect to Sentinel IPC.", file=sys.stderr)
                sys.exit(1)
            time.sleep(0.5)

    # --- Step 3: Get license info ---
    license_resp = ipc_call(sock, "get_license")
    if license_resp["status"] != "ok":
        print(f"License error: {license_resp.get('error')}", file=sys.stderr)
        sys.exit(1)

    license_info = license_resp["license"]
    print(f"Licensed to org: {license_info['org_id']}")
    print(f"License type: {license_info['license_type']}")
    print(f"Expires: {license_info['expiry_date']}")

    # --- Step 4: Get features and configure ---
    features_resp = ipc_call(sock, "get_features")
    if features_resp["status"] != "ok":
        print(f"Features error: {features_resp.get('error')}", file=sys.stderr)
        sys.exit(1)

    features = features_resp["features"]
    print(f"Features: {features}")

    tier = features.get("tier", "basic")
    max_users = features.get("max_users", 1)
    print(f"Running in {tier} mode with max {max_users} users")

    # --- Step 5: Health check in background ---
    running = True

    def health_loop():
        while running:
            time.sleep(30)
            try:
                resp = ipc_call(sock, "health")
                if resp["status"] != "ok":
                    print("Sentinel health check failed.", file=sys.stderr)
                    os._exit(1)
            except Exception:
                print("Lost connection to Sentinel.", file=sys.stderr)
                os._exit(1)

    threading.Thread(target=health_loop, daemon=True).start()

    # --- Step 6: Handle SIGTERM ---
    def on_sigterm(signum, frame):
        nonlocal running
        running = False
        print("Shutting down gracefully...")
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, on_sigterm)

    # --- Step 7: Your application logic here ---
    print("Application running. Press Ctrl+C to stop.")
    try:
        while running:
            time.sleep(1)
            # ... your main loop ...
    except KeyboardInterrupt:
        pass
    finally:
        running = False
        sock.close()


if __name__ == "__main__":
    main()
```

### 14.7 Minimal Complete Integration Example (Go)

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type IPCResponse struct {
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

func ipcCall(conn net.Conn, method string) (*IPCResponse, error) {
	req, _ := json.Marshal(map[string]string{"method": method})
	req = append(req, '\n')
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write to sentinel: %w", err)
	}
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return nil, fmt.Errorf("read from sentinel: connection lost")
	}
	var resp IPCResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse sentinel response: %w", err)
	}
	return &resp, nil
}

func main() {
	// Step 1: Read IPC socket path
	socketPath := os.Getenv("SENTINEL_IPC_SOCKET")
	if socketPath == "" {
		log.Fatal("Must be launched by Sentinel DRM client (SENTINEL_IPC_SOCKET not set)")
	}

	// Step 2: Connect with retry
	var conn net.Conn
	var err error
	for i := 0; i < 5; i++ {
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		log.Fatalf("Cannot connect to Sentinel IPC: %v", err)
	}
	defer conn.Close()

	// Step 3: Get license
	licResp, err := ipcCall(conn, "get_license")
	if err != nil {
		log.Fatalf("IPC get_license failed: %v", err)
	}
	if licResp.Status != "ok" {
		log.Fatalf("License error: %s", licResp.Error)
	}
	fmt.Printf("Licensed to org: %s\n", licResp.License.OrgID)
	fmt.Printf("License type: %s, expires: %s\n", licResp.License.LicenseType, licResp.License.ExpiryDate)

	// Step 4: Get features
	featResp, err := ipcCall(conn, "get_features")
	if err != nil {
		log.Fatalf("IPC get_features failed: %v", err)
	}
	if featResp.Status != "ok" {
		log.Fatalf("Features error: %s", featResp.Error)
	}
	fmt.Printf("Features: %v\n", featResp.Features)

	// Step 5: Handle SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Step 6: Background health check
	go func() {
		for {
			time.Sleep(30 * time.Second)
			resp, err := ipcCall(conn, "health")
			if err != nil || resp.Status != "ok" {
				log.Println("Sentinel health check failed, shutting down")
				os.Exit(1)
			}
		}
	}()

	// Step 7: Main application loop
	fmt.Println("Application running...")
	<-sigCh
	fmt.Println("Shutting down gracefully...")
}
```
