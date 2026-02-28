# Sentinel DRM Client — Claude Context

Sentinel DRM is QNu Labs' multi-tenant Digital Rights Management platform for license issuance, software distribution, and runtime license enforcement for enterprise clients.
This is the Sentinel client — a Go binary that enforces licensing on customer machines by validating license files, launching licensed software as a child process, and communicating with the DRM backend for activation and heartbeats.

---

## Implementation Status

All 8 phases are complete.
See `IMPLEMENTATION_PLAN.md` for full architecture and `phases/phase-*.md` for per-phase details.

---

## Tech Stack

- **Language**: Go 1.25+
- **CLI**: `github.com/spf13/cobra` — single root command with `--license` and `--software` flags
- **UUID**: `github.com/google/uuid` — machine IDs and request nonces
- **Memory security**: `github.com/awnumar/memguard` — locked buffers for EC private key material
- **Windows IPC**: `github.com/Microsoft/go-winio` — named pipe support (build-tagged Windows-only)
- **Obfuscation**: `mvdan.cc/garble` — build tool (not a library dep), used in production builds

---

## Project Structure

```
sentinel-drm-client/
├── cmd/sentinel/main.go              # Entry point, cobra CLI, ldflags vars
├── internal/
│   ├── config/config.go              # Config struct, flag validation
│   ├── crypto/crypto.go              # EC keys, ECDSA, base64url, canonical JSON, SHA-256
│   ├── license/license.go            # .lic file parsing, signature verification, payload validation
│   ├── hardware/
│   │   ├── hardware.go               # CollectFingerprint(), GetMachineID()
│   │   ├── hardware_linux.go         # DMI UUID, findmnt+sysfs, /etc/machine-id
│   │   ├── hardware_darwin.go        # ioreg, diskutil, IOPlatformUUID
│   │   └── hardware_windows.go       # PowerShell Get-CimInstance, registry
│   ├── keystore/keystore.go          # AES-256-GCM encrypted file-based keystore
│   ├── state/state.go                # Encrypted local state (activation, grace period)
│   ├── drm/drm.go                    # Server communication (activate, heartbeat, decommission)
│   ├── process/
│   │   ├── process.go                # Launch, Wait, Exited, VerifyBinaryChecksum
│   │   ├── process_unix.go           # Stop(): SIGTERM → 10s → SIGKILL
│   │   └── process_windows.go        # Stop(): direct Kill()
│   ├── ipc/
│   │   ├── ipc.go                    # JSON-over-newline protocol, Server, degradation stubs
│   │   ├── ipc_unix.go               # Unix domain socket listener
│   │   └── ipc_windows.go            # Named pipe listener (go-winio)
│   ├── sentinel/sentinel.go          # Main orchestrator (STANDARD + HARDWARE_BOUND flows)
│   └── antitamper/
│       ├── antitamper.go             # Monitor, degradation state machine
│       ├── antitamper_linux.go       # TracerPid check
│       ├── antitamper_darwin.go      # sysctl P_TRACED check
│       ├── antitamper_windows.go     # IsDebuggerPresent check
│       └── antitamper_other.go       # no-op fallback
├── phases/                           # Per-phase implementation specs
├── go.mod
├── go.sum
├── IMPLEMENTATION_PLAN.md
└── CLAUDE.md
```

A `Makefile` exists with `build`, `build-prod`, `build-all` (5 platforms), `test`, `lint`, `fmt`, `clean`, `deps` targets.

---

## Build & Run

### Build-time variables (ldflags)

Two variables are injected at build time:
```go
var orgPublicKeyPEM string  // -X main.orgPublicKeyPEM=<PEM>
var version string          // -X main.version=<version>
```

The binary **will not start** if `orgPublicKeyPEM` is empty or not a valid EC P-256 public key.

### Development build

```bash
go build -ldflags "-X 'main.orgPublicKeyPEM=$(cat org_pubkey.pem)' -X 'main.version=dev'" \
  -o bin/sentinel ./cmd/sentinel
```

### Running

```bash
./bin/sentinel --license /path/to/license.lic --software /path/to/binary
```

Both flags are required. The server URL (for STANDARD licenses) comes from the license file, not CLI flags.

### Tests

```bash
go test ./... -v -count=1
```

Tests exist for: `crypto` (14), `license` (16), `state` (11), `drm` (12), `process` (5), `ipc` (7).

### Production build (Phase 8, not yet available)

```bash
garble -literals -tiny -seed=random build \
  -ldflags "-X 'main.orgPublicKeyPEM=...' -X 'main.version=1.0.0'" \
  -o bin/sentinel ./cmd/sentinel
```

---

## How It Works

### STANDARD License Flow

1. Parse and verify license file (ECDSA signature + expiry check)
2. Init keystore (vault key derived from `hardware.GetMachineID()`)
3. Load or generate machine EC keypair (stored encrypted in keystore)
4. Load or create encrypted state file
5. Detect license key change → reset activation state
6. Create DRM client using `license.ServerURL`
7. Activate with server if not yet activated
8. Mandatory startup heartbeat (no grace allowed if already exhausted)
9. Launch software with `SENTINEL_IPC_SOCKET` env var
10. Start IPC server + heartbeat loop goroutines
11. Wait for: software exit, fatal heartbeat failure, or SIGINT/SIGTERM

### HARDWARE_BOUND License Flow

1. Parse and verify license file (signature + expiry)
2. Collect hardware fingerprint, compare with license
3. Launch software (fingerprint used as IPC machine ID)
4. Start IPC server
5. Wait for software exit or signal — fully offline, no server communication

### Grace Period (STANDARD only)

- Total quota: `heartbeat_grace_period_days * 86400` seconds
- Each missed heartbeat (connection error) consumes `heartbeat_interval_minutes * 60` seconds
- Server errors (HTTP 4xx/5xx) do NOT consume grace
- Successful heartbeat preserves remaining quota (does NOT reset to full)
- Once exhausted (`grace_exhausted = true`): next single connection miss = immediate shutdown
- Startup always contacts server — prevents restart cycling to abuse grace

---

## Key Modules Quick Reference

| Module       | What it does                                           | Key functions                                                                                      |
| ------------ | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `crypto`     | All cryptographic primitives                           | `CanonicalJSON`, `VerifyECDSA`, `SignECDSA`, `SHA256File`, `Base64URLEncode/Decode`                |
| `license`    | License file loading and validation                    | `LoadAndVerify(path, pubKey)`, `IsExpired(payload)`                                                |
| `hardware`   | Platform-specific hardware fingerprinting              | `CollectFingerprint()`, `GetMachineID()`                                                           |
| `keystore`   | AES-256-GCM encrypted key-value file store             | `New(path, vaultKey)`, `Store/Retrieve/Delete`, `DeriveVaultKey(machineID)`                        |
| `state`      | Encrypted activation/grace state persistence           | `NewStateManager(ks)`, `Load()`, `Save(state)`, `Delete()`                                         |
| `drm`        | Signed HTTP communication with DRM backend             | `Activate()`, `Heartbeat()`, `DecommissionAck()`, `IsConnectionError()`                            |
| `process`    | Child process lifecycle management                     | `Launch(path, env)`, `Stop()`, `Exited()`, `VerifyBinaryChecksum()`                                |
| `ipc`        | JSON-over-socket IPC for managed software              | `NewServer()`, `Serve(ctx)`, `SetDegradeStage()`, methods: `get_license`, `get_features`, `health` |
| `sentinel`   | Main orchestrator wiring everything together           | `New(cfg, pubKey)`, `Run(ctx)`, `SetupSignalHandler()`                                             |
| `antitamper` | Debugger detection and progressive service degradation | `NewMonitor(ipcServer)`, `Start(ctx)`, `IsCompromised()`                                           |

---

## Critical Implementation Details

### Canonical JSON compatibility

`crypto.CanonicalJSON` MUST produce byte-identical output to Python's `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. This includes:
- Sorted keys at all nesting levels
- Compact separators (no spaces)
- Non-ASCII characters escaped to `\uXXXX` (Go does NOT do this by default)

### Signature verification

License and DRM response signatures are over the **base64url-encoded payload string**, NOT the decoded JSON bytes.

### DRM request signing

Every request carries headers: `X-Sentinel-Machine-Id`, `X-Sentinel-Timestamp`, `X-Sentinel-Nonce`, `X-Sentinel-Signature`.
Signing string format: `{METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256_HEX(BODY)}`

### Platform-specific files

Build-tagged files handle: hardware fingerprinting (linux/darwin/windows), process stop behavior (unix/windows), IPC transport (unix socket/named pipe).

---

## Stored Data Locations

| Data       | Linux                                      | macOS                                                     | Windows                               |
| ---------- | ------------------------------------------ | --------------------------------------------------------- | ------------------------------------- |
| Keystore   | `~/.local/share/sentinel-drm/keystore.enc` | `~/Library/Application Support/sentinel-drm/keystore.enc` | `%APPDATA%\sentinel-drm\keystore.enc` |
| State      | `~/.local/share/sentinel-drm/state.enc`    | `~/Library/Application Support/sentinel-drm/state.enc`    | `%APPDATA%\sentinel-drm\state.enc`    |
| IPC socket | `/tmp/sentinel-<machine_id>.sock`          | `/tmp/sentinel-<machine_id>.sock`                         | `\\.\pipe\sentinel-<machine_id>`      |

---

## Coding Preferences

1. Ask clarification questions in the planning phase before starting implementation.
2. If certain points of the task are ambiguous, ask the user for clarification rather than assuming.
3. Validate first, fail fast and loud. Do not try to circumvent improper inputs or undefined behaviors.
4. Do not add unnecessary fallbacks or defaults. They create bloat and introduce silent bugs.
5. Keep code lean and clean. Add documentation only where necessary, do not add unnecessary comments.
6. Prefer stdlib. Introduce deps only with clear payoff.
7. Do not run commands that modify the project or add packages on your own. Ask the user to run them instead, giving a proper reason.
8. Do not perform premature optimization. Create functionality in a simple and robust way first, then ask the user if further optimization is required.
