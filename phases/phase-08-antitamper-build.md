# Phase 8 — Anti-Tamper, Degradation, and Build System

**Status**: Complete
**Depends on**: Phase 6 (IPC), Phase 7 (orchestrator)

---

## Goals

- Detect debuggers and tampering attempts at runtime on Linux, macOS, and Windows.
- On detection, progressively degrade service (not immediate kill) to frustrate
  reverse engineering.
- Set up the Makefile for garble-obfuscated cross-compilation builds.

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/antitamper/antitamper.go` | Created — monitor orchestrator, degradation state machine |
| `internal/antitamper/antitamper_linux.go` | Created — TracerPid detection |
| `internal/antitamper/antitamper_darwin.go` | Created — sysctl P_TRACED detection |
| `internal/antitamper/antitamper_windows.go` | Created — IsDebuggerPresent detection |
| `internal/antitamper/antitamper_other.go` | Created — no-op fallback for unsupported platforms |
| `internal/sentinel/sentinel.go` | Modified — start anti-tamper monitor in both license flows |
| `cmd/sentinel/main.go` | Modified — unescape PEM newlines embedded by Makefile |
| `Makefile` | Created — dev build, garble prod build, cross-compilation |

---

## Anti-Tamper Design Philosophy

**Do NOT immediately kill on detection.** Instead, progressively degrade the service
over several minutes. This approach:

1. Makes it harder for crackers to identify exactly which check triggered the protection.
2. Creates an ambiguous experience — "is this a bug or protection?" delays understanding.
3. The software itself (via IPC) also receives degraded data, causing downstream weirdness
   that is even harder to correlate with the Sentinel Client's anti-tamper logic.
4. Eventually crashes in a way that looks like a plausible system error, not an
   intentional kill.

---

## Detection Methods — Platform-Specific

### Linux — `antitamper_linux.go`

#### TracerPid Check

Read `/proc/self/status` and check the `TracerPid` field. A non-zero value means
a debugger (ptrace) is attached.

```go
//go:build linux

func isDebuggerAttached() bool {
    data, err := os.ReadFile("/proc/self/status")
    if err != nil {
        return false // can't check, assume safe
    }
    for _, line := range strings.Split(string(data), "\n") {
        if strings.HasPrefix(line, "TracerPid:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 && fields[1] != "0" {
                return true
            }
        }
    }
    return false
}
```

**Note**: Only the TracerPid check is implemented. The ptrace self-check
(`PTRACE_TRACEME`) was considered but rejected — it is unsafe in Go's multithreaded
runtime and can interfere with the Go scheduler.

---

### macOS — `antitamper_darwin.go`

#### sysctl P_TRACED Check

Use `unix.SysctlKinfoProc` to query the kernel for our process info and check the
`P_TRACED` flag.

```go
//go:build darwin

import (
    "os"
    "golang.org/x/sys/unix"
)

// pTraced is the P_TRACED flag from <sys/proc.h>. Set by the kernel when a
// debugger is attached. Not exported by golang.org/x/sys/unix.
const pTraced = 0x00000800

func isDebuggerAttached() bool {
    info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
    if err != nil {
        return false // cannot determine, assume safe
    }
    return info.Proc.P_flag&pTraced != 0
}
```

**Important**: The following constants are **not exported** by `golang.org/x/sys/unix`
for darwin and must be used as raw values:
- `KERN_PROC` = 14, `KERN_PROC_PID` = 1 (use `unix.SysctlKinfoProc` instead — it handles
  the MIB translation internally)
- `P_TRACED` = `0x00000800` — defined locally as `pTraced`

The `KinfoProc` struct field is `info.Proc.P_flag` (`Proc` of type `ExternProc`,
field `P_flag int32`). The previously documented `info.Kproc` name is incorrect.

---

### Windows — `antitamper_windows.go`

#### IsDebuggerPresent + CheckRemoteDebuggerPresent

```go
//go:build windows

import (
    "unsafe"
    "golang.org/x/sys/windows"
)

var (
    kernel32                       = windows.NewLazyDLL("kernel32.dll")
    procIsDebuggerPresent          = kernel32.NewProc("IsDebuggerPresent")
    procCheckRemoteDebuggerPresent = kernel32.NewProc("CheckRemoteDebuggerPresent")
)

func isDebuggerAttached() bool {
    // Check for a local debugger (e.g. WinDbg, x64dbg attached locally).
    ret, _, _ := procIsDebuggerPresent.Call()
    if ret != 0 {
        return true
    }

    // Check for a remote debugger attached via the debug API.
    var isRemote int32
    ret, _, _ = procCheckRemoteDebuggerPresent.Call(
        uintptr(windows.CurrentProcess()),
        uintptr(unsafe.Pointer(&isRemote)),
    )
    if ret != 0 && isRemote != 0 {
        return true
    }

    return false
}
```

---

### Other platforms — `antitamper_other.go`

A no-op fallback for any platform that is not linux, darwin, or windows.

```go
//go:build !linux && !darwin && !windows

func isDebuggerAttached() bool {
    return false
}
```

---

## Monitor — `antitamper.go`

### Monitor Struct

```go
type Monitor struct {
    ipcServer  *ipc.Server
    detected   atomic.Bool
    stage      atomic.Int32
    detectedAt time.Time
}

func NewMonitor(ipcServer *ipc.Server) *Monitor
func (m *Monitor) Start(ctx context.Context)
func (m *Monitor) IsCompromised() bool
```

### `Start(ctx context.Context)`

Runs in a goroutine. Checks for tampering immediately at startup, then periodically
with random jitter.

```go
func (m *Monitor) Start(ctx context.Context) {
    // Check immediately at startup before entering the loop.
    if isDebuggerAttached() {
        m.onDetected(ctx)
    }

    for {
        // Random interval: 5-10 seconds (unpredictable timing)
        jitter := time.Duration(5+rand.Intn(6)) * time.Second

        select {
        case <-ctx.Done():
            return
        case <-time.After(jitter):
            if isDebuggerAttached() {
                m.onDetected(ctx)
            }
            if m.detected.Load() {
                m.progressDegradation()
            }
        }
    }
}
```

### `onDetected(ctx context.Context)`

Called on first detection. Sets the detection flag, records the timestamp, advances
to `StageWarnings`, and starts the warning emission goroutine.

```go
func (m *Monitor) onDetected(ctx context.Context) {
    if m.detected.CompareAndSwap(false, true) {
        m.detectedAt = time.Now()
        m.stage.Store(int32(ipc.StageWarnings))
        m.ipcServer.SetDegradeStage(ipc.StageWarnings)
        go m.warningLoop(ctx)
    }
}
```

**Note**: `onDetected` takes `ctx context.Context` so it can pass it to the warning
goroutine. The ctx is needed for clean shutdown when the process exits normally.

### `progressDegradation()`

Advances through degradation stages based on time elapsed since detection. A ±30s
jitter is applied on every call so stage transitions are not predictable.

```go
func (m *Monitor) progressDegradation() {
    // ±30s jitter so attackers cannot fingerprint the exact transition timing.
    jitterSecs := rand.Intn(61) - 30
    adjustedElapsed := time.Since(m.detectedAt) + time.Duration(jitterSecs)*time.Second
    if adjustedElapsed < 0 {
        adjustedElapsed = 0
    }

    var newStage ipc.DegradeStage
    switch {
    case adjustedElapsed < 2*time.Minute:
        newStage = ipc.StageWarnings
    case adjustedElapsed < 5*time.Minute:
        newStage = ipc.StageErrors
    case adjustedElapsed < 10*time.Minute:
        newStage = ipc.StageSlowdown
    default:
        newStage = ipc.StageCrash
    }

    currentStage := ipc.DegradeStage(m.stage.Load())
    if newStage > currentStage {
        m.stage.Store(int32(newStage))
        m.ipcServer.SetDegradeStage(newStage)
        m.applyStage(newStage)
    }
}
```

---

## Degradation Stages

### Stage 1: `StageWarnings` (0-2 minutes after detection)

A dedicated goroutine (`warningLoop`) is started by `onDetected`. It emits cryptic
warning messages to stderr every 15-30 seconds (randomised). The messages look like
plausible system warnings, not anti-tamper messages.

```go
func (m *Monitor) warningLoop(ctx context.Context) {
    for {
        delay := time.Duration(15+rand.Intn(16)) * time.Second
        select {
        case <-ctx.Done():
            return
        case <-time.After(delay):
            currentStage := ipc.DegradeStage(m.stage.Load())
            emitWarning(currentStage)
        }
    }
}

var warningMessages = []string{
    "WARNING: memory integrity check: segment checksum recalculating...",
    "WARN: unexpected TLB flush in secure region",
    "caution: runtime verification handshake delayed",
    "NOTE: entropy pool reseeding (source: hardware)",
    "WARN: secure context migration pending",
}
```

### Stage 2: `StageErrors` (2-5 minutes after detection)

The `warningLoop` goroutine escalates to error-level messages once `StageErrors` is
reached (it reads the current stage on every iteration). IPC responses are degraded
via `SetDegradeStage` (implemented in Phase 6).

```go
var errorMessages = []string{
    "ERROR: ENOMEM in secure allocator (pool exhausted)",
    "error: EACCES verifying runtime signature (retrying...)",
    "FATAL: page fault in protected region 0x7fff...",
    "error: secure channel handshake timeout (attempt 3/5)",
}

func emitWarning(stage ipc.DegradeStage) {
    var msgs []string
    if stage >= ipc.StageErrors {
        msgs = errorMessages
    } else {
        msgs = warningMessages
    }
    fmt.Fprintf(os.Stderr, "%s\n", msgs[rand.Intn(len(msgs))])
}
```

IPC behavior at this stage (implemented in Phase 6 `handleRequest`):
- `get_features` returns empty features map
- `get_license` intermittently returns `{status: "error", error: "license validation failed"}`
- ~30% of requests fail with a random system error

### Stage 3: `StageSlowdown` (5-10 minutes after detection)

`applyStage` calls `applySlowdown()` which starts intentionally-leaking goroutines
that waste memory and CPU.

```go
func applySlowdown() {
    // Memory waste: allocate 50 MB in 1 MB chunks over ~25-75 seconds.
    go func() {
        var waste [][]byte
        for i := 0; i < 50; i++ {
            chunk := make([]byte, 1<<20) // 1 MB
            _, _ = crand.Read(chunk)     // crypto/rand fill to prevent optimization
            waste = append(waste, chunk)
            time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
        }
        runtime.KeepAlive(waste)
    }()

    // CPU busy loops in 2 goroutines: hash 4 KB buffers in a tight loop.
    for i := 0; i < 2; i++ {
        go func() {
            for {
                _ = sha256.Sum256(make([]byte, 4096))
                time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
            }
        }()
    }
}
```

**Note**: `crypto/rand.Read` is used (not `math/rand.Read`, which was deprecated in
Go 1.20 and removed in later versions).

### Stage 4: `StageCrash` (10+ minutes after detection)

`applyStage` starts `triggerCrash()` in a goroutine. It adds a random 0-60s delay
then exits with code 137 (looks like an OOM kill: SIGKILL = 128 + 9).

```go
func triggerCrash() {
    delay := time.Duration(rand.Intn(60)) * time.Second
    time.Sleep(delay)

    crashMessages := []string{
        "FATAL: out of memory in secure allocator",
        "PANIC: stack corruption detected in runtime verifier",
        "FATAL: unable to recover from page fault in protected region",
    }
    fmt.Fprintf(os.Stderr, "%s\n", crashMessages[rand.Intn(len(crashMessages))])
    os.Exit(137)
}
```

---

## Integration with Orchestrator

In `internal/sentinel/sentinel.go`, the anti-tamper monitor is started after the
IPC server in both `runStandard` and `runHardwareBound`:

```go
go ipcSrv.Serve(ctx)
go antitamper.NewMonitor(ipcSrv).Start(ctx)
```

---

## PEM Embedding in main.go

The Makefile embeds the org public key PEM with literal `\n` characters (to avoid
shell quoting issues with multiline strings in `-ldflags`). `main.go` must unescape
them before parsing:

```go
// The Makefile embeds the PEM with literal \n to avoid shell quoting issues.
// Restore real newlines before parsing.
orgPublicKeyPEM = strings.ReplaceAll(orgPublicKeyPEM, `\n`, "\n")
```

This is applied in the `run()` function immediately after the empty-check, before
`crypto.ParseECPublicKeyPEM`.

---

## Makefile

```makefile
VERSION ?= dev
# Path to the org's EC P-256 public key PEM file.
# Usage: make build-prod ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem VERSION=1.0.0
ORG_PUBLIC_KEY_PEM_FILE ?=

# Convert the PEM file's real newlines to literal \n for ldflags single-line embedding.
# main.go unescapes \n back to real newlines at startup.
_PEM_ESCAPED := $(if $(ORG_PUBLIC_KEY_PEM_FILE),$(shell awk 'BEGIN{ORS="\\n"} 1' "$(ORG_PUBLIC_KEY_PEM_FILE)"),)

LDFLAGS := -X 'main.orgPublicKeyPEM=$(_PEM_ESCAPED)' \
           -X 'main.version=$(VERSION)'

# ── Development ──────────────────────────────────────────────
.PHONY: build
build:
    go build -ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

.PHONY: build-prod
build-prod:
    garble -literals -tiny -seed=random build \
        -ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

# Cross-compilation targets (5 platforms), test, lint, fmt, clean, deps
# See Makefile for full content.
```

### Why `ORG_PUBLIC_KEY_PEM_FILE` instead of inline PEM

Passing a multiline PEM string directly on the command line
(`ORG_PUBLIC_KEY_PEM="$(cat key.pem)"`) breaks shell quoting because the PEM contains
real newlines. Using a file path avoids this: the Makefile reads the file via `awk`
and replaces each newline with a literal `\n` before passing the value to `-ldflags`.

### Garble Flags

| Flag | Purpose |
|---|---|
| `-literals` | Obfuscate string literals. **Critical** — hides the embedded public key PEM, error messages, and API paths in the binary. |
| `-tiny` | Strip file names, line numbers, and other debug info. Reduces binary size and makes stack traces opaque. |
| `-seed=random` | Randomize obfuscation seed per build. Prevents pattern recognition across builds. |

### Go Version Requirement

Garble patches the Go linker and requires explicit support for each Go version.
The Makefile and module are pinned to **Go 1.25.7** (`go 1.25.0` + `toolchain go1.25.7`
in `go.mod`).

- Garble v0.15.0 supports Go ≤ 1.25. **Go 1.26+ breaks garble** with
  `"Go linker patches aren't available for go1.26 or later yet"`.
- Garble itself requires Go ≥ 1.25 to compile (its own `go.mod` minimum).
- Do not upgrade Go past 1.25 until garble releases support for the new version.

### Build Usage

**Dev build** (no obfuscation, fast):
```bash
make build ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem
```

**Production build for a specific org**:
```bash
make build-prod ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem VERSION=1.0.0
```

**All platforms**:
```bash
make build-all ORG_PUBLIC_KEY_PEM_FILE=org_pubkey.pem VERSION=1.0.0
```

### Garble Installation

Garble is a build tool, not a library dependency. Install it with Go 1.25:
```bash
go install mvdan.cc/garble@latest
```

---

## Future Improvements (Not in v1)

These are noted for future phases:

1. **Binary self-hash verification**: At startup, compute SHA-256 of own binary
   on disk and compare against an expected hash embedded at build time. Detects
   binary patching. Requires build pipeline to compute and embed the hash.

2. **LD_PRELOAD / DYLD_INSERT_LIBRARIES detection** (Linux/macOS): Check environment
   variables and `/proc/self/maps` for injected shared libraries.

3. **VM / sandbox detection**: Detect common virtualization artifacts (hypervisor CPUID
   flag, VM-specific hardware, sandbox directories).

4. **Clock tampering protection**: Use TPM 2.0 monotonic counters for tamper-resistant
   time anchoring on hardware-bound licenses.

---

## Done Criteria

- [x] `isDebuggerAttached()` returns false in normal execution
- [x] `isDebuggerAttached()` returns true when a debugger is attached (manual test)
- [x] Degradation stages progress over time after detection
- [x] `StageWarnings`: warning messages appear on stderr (separate goroutine, 15-30s interval)
- [x] `StageErrors`: IPC responses are intermittently corrupted/missing
- [x] `StageSlowdown`: CPU and memory usage visibly increase
- [x] `StageCrash`: process exits with a plausible error after delay (exit code 137)
- [x] Anti-tamper monitor runs with random jitter (5-10s interval, ±30s stage transition jitter)
- [x] `make build ORG_PUBLIC_KEY_PEM_FILE=...` produces a working binary with embedded public key
- [x] `make build-prod ORG_PUBLIC_KEY_PEM_FILE=...` produces a garble-obfuscated binary
- [x] `make build-all ORG_PUBLIC_KEY_PEM_FILE=...` produces binaries for all 5 platforms
- [x] Garble `-literals` flag hides string literals (verify with `strings` command)
- [x] Garble tool installed with `go install mvdan.cc/garble@latest` (Go 1.25 required)
