# Phase 8 — Anti-Tamper, Degradation, and Build System

**Status**: Pending
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
| `internal/antitamper/antitamper_linux.go` | Created — ptrace/TracerPid detection |
| `internal/antitamper/antitamper_darwin.go` | Created — sysctl P_TRACED detection |
| `internal/antitamper/antitamper_windows.go` | Created — IsDebuggerPresent detection |
| `internal/sentinel/sentinel.go` | Modified — start anti-tamper monitor |
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

#### Ptrace Self-Check

Attempt to ptrace self. If it fails with `EPERM`, another process is already
tracing us.

```go
func isPtraceBlocked() bool {
    // Try PTRACE_TRACEME — fails if already being traced
    err := syscall.PtraceAttach(os.Getpid())
    if err != nil {
        return true // already being traced
    }
    syscall.PtraceDetach(os.Getpid())
    return false
}
```

**Note**: `PTRACE_TRACEME` is a better approach. The implementation should use
the appropriate ptrace call for the Go runtime context. This may need `runtime.LockOSThread()`.

---

### macOS — `antitamper_darwin.go`

#### sysctl P_TRACED Check

Use the `sysctl` system call to check for the `P_TRACED` flag on our own process.

```go
//go:build darwin

import "golang.org/x/sys/unix"

func isDebuggerAttached() bool {
    var info unix.KinfoProc
    mib := [4]int32{unix.CTL_KERN, unix.KERN_PROC, unix.KERN_PROC_PID, int32(os.Getpid())}

    n := uintptr(unsafe.Sizeof(info))
    _, _, errno := unix.Syscall6(
        unix.SYS___SYSCTL,
        uintptr(unsafe.Pointer(&mib[0])),
        4,
        uintptr(unsafe.Pointer(&info)),
        uintptr(unsafe.Pointer(&n)),
        0, 0,
    )
    if errno != 0 {
        return false
    }

    return info.Kproc.P_flag&unix.P_TRACED != 0
}
```

**Note**: This requires `golang.org/x/sys/unix`. The exact struct layout and
constant names may vary — verify against the Go sys package documentation.
If `x/sys` is too heavy, an alternative is to shell out to
`sysctl kern.proc.pid.<pid>` and parse the output.

---

### Windows — `antitamper_windows.go`

#### IsDebuggerPresent + CheckRemoteDebuggerPresent

```go
//go:build windows

import "golang.org/x/sys/windows"

var (
    kernel32                     = windows.NewLazyDLL("kernel32.dll")
    procIsDebuggerPresent        = kernel32.NewProc("IsDebuggerPresent")
    procCheckRemoteDebuggerPresent = kernel32.NewProc("CheckRemoteDebuggerPresent")
)

func isDebuggerAttached() bool {
    // Check for local debugger
    ret, _, _ := procIsDebuggerPresent.Call()
    if ret != 0 {
        return true
    }

    // Check for remote debugger
    var isRemoteDebugger int32
    ret, _, _ = procCheckRemoteDebuggerPresent.Call(
        uintptr(windows.CurrentProcess()),
        uintptr(unsafe.Pointer(&isRemoteDebugger)),
    )
    if ret != 0 && isRemoteDebugger != 0 {
        return true
    }

    return false
}
```

---

## Monitor — `antitamper.go`

### Monitor Struct

```go
type Monitor struct {
    ipcServer   *ipc.Server
    detected    atomic.Bool
    stage       atomic.Int32
    detectedAt  time.Time
}

func NewMonitor(ipcServer *ipc.Server) *Monitor
func (m *Monitor) Start(ctx context.Context)
func (m *Monitor) IsCompromised() bool
```

### `Start(ctx context.Context)`

Runs in a goroutine. Periodically checks for tampering and manages degradation.

```go
func (m *Monitor) Start(ctx context.Context) {
    // Initial check at startup
    if isDebuggerAttached() {
        m.onDetected()
    }

    for {
        // Random interval: 5-10 seconds (unpredictable timing)
        jitter := time.Duration(5+rand.Intn(6)) * time.Second

        select {
        case <-ctx.Done():
            return
        case <-time.After(jitter):
            if isDebuggerAttached() {
                m.onDetected()
            }
            if m.detected.Load() {
                m.progressDegradation()
            }
        }
    }
}
```

### `onDetected()`

Called on first detection. Sets the detection flag and timestamp.

```go
func (m *Monitor) onDetected() {
    if m.detected.CompareAndSwap(false, true) {
        m.detectedAt = time.Now()
        m.stage.Store(int32(ipc.StageWarnings))
        m.ipcServer.SetDegradeStage(ipc.StageWarnings)
    }
}
```

### `progressDegradation()`

Advances through degradation stages based on time elapsed since detection.

```go
func (m *Monitor) progressDegradation() {
    elapsed := time.Since(m.detectedAt)
    var newStage ipc.DegradeStage

    switch {
    case elapsed < 2*time.Minute:
        newStage = ipc.StageWarnings
    case elapsed < 5*time.Minute:
        newStage = ipc.StageErrors
    case elapsed < 10*time.Minute:
        newStage = ipc.StageSlowdown
    default:
        newStage = ipc.StageCrash
    }

    // Add random jitter to stage transitions (±30 seconds)
    // so timing isn't predictable

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

Emit occasional mysterious warning messages to stderr. These should look like
plausible system warnings, not anti-tamper messages.

```go
var warningMessages = []string{
    "WARNING: memory integrity check: segment checksum recalculating...",
    "WARN: unexpected TLB flush in secure region",
    "caution: runtime verification handshake delayed",
    "NOTE: entropy pool reseeding (source: hardware)",
    "WARN: secure context migration pending",
}

func emitWarning() {
    msg := warningMessages[rand.Intn(len(warningMessages))]
    fmt.Fprintf(os.Stderr, "%s\n", msg)
}
```

Frequency: every 15-30 seconds (random).

### Stage 2: `StageErrors` (2-5 minutes after detection)

Inject fake errors into IPC responses (handled by IPC server via `SetDegradeStage`).
Also emit error-like messages to stderr.

```go
var errorMessages = []string{
    "ERROR: ENOMEM in secure allocator (pool exhausted)",
    "error: EACCES verifying runtime signature (retrying...)",
    "FATAL: page fault in protected region 0x7fff...",
    "error: secure channel handshake timeout (attempt 3/5)",
}
```

IPC behavior at this stage (implemented in Phase 6 `handleRequest`):
- `get_features` returns partial features (randomly drop keys)
- `get_license` intermittently returns `{status: "error", error: "internal error"}`
- About 30% of requests fail with random errors

### Stage 3: `StageSlowdown` (5-10 minutes after detection)

Artificially increase resource usage to make the process appear unstable.

```go
func applySlowdown() {
    // Allocate memory in goroutines
    go func() {
        var waste [][]byte
        for i := 0; i < 50; i++ {
            chunk := make([]byte, 1<<20) // 1MB chunks
            rand.Read(chunk)             // fill to prevent optimization
            waste = append(waste, chunk)
            time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
        }
        runtime.KeepAlive(waste)
    }()

    // CPU busy loops in goroutines
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

### Stage 4: `StageCrash` (10+ minutes after detection)

Terminate with a plausible-looking system error. Add some randomized delay (0-60s)
so the exact crash time is unpredictable.

```go
func triggerCrash() {
    delay := time.Duration(rand.Intn(60)) * time.Second
    time.Sleep(delay)

    crashMessages := []string{
        "FATAL: out of memory in secure allocator",
        "PANIC: stack corruption detected in runtime verifier",
        "FATAL: unable to recover from page fault in protected region",
    }
    msg := crashMessages[rand.Intn(len(crashMessages))]
    fmt.Fprintf(os.Stderr, "%s\n", msg)
    os.Exit(137) // looks like OOM kill (SIGKILL = 128 + 9)
}
```

---

## Integration with Orchestrator

In `internal/sentinel/sentinel.go`, start the anti-tamper monitor after launching
the IPC server:

```go
// After IPC server is started
monitor := antitamper.NewMonitor(s.ipcServer)
go monitor.Start(ctx)
```

This applies to both STANDARD and HARDWARE_BOUND flows.

---

## Makefile

```makefile
VERSION ?= dev
ORG_PUBLIC_KEY_PEM ?=

# Escape newlines in PEM for ldflags
LDFLAGS := -X 'main.orgPublicKeyPEM=$(ORG_PUBLIC_KEY_PEM)' \
           -X 'main.version=$(VERSION)'

# ── Development ──────────────────────────────────────────────

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

.PHONY: test
test:
	go test ./... -v -count=1

.PHONY: lint
lint:
	go vet ./...

# ── Production (garble-obfuscated) ───────────────────────────

.PHONY: build-prod
build-prod:
	garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel ./cmd/sentinel

# ── Cross-compilation (garble, all 5 platforms) ──────────────

.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-linux-amd64 ./cmd/sentinel

.PHONY: build-linux-arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-linux-arm64 ./cmd/sentinel

.PHONY: build-darwin-arm64
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-darwin-arm64 ./cmd/sentinel

.PHONY: build-windows-amd64
build-windows-amd64:
	GOOS=windows GOARCH=amd64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-windows-amd64.exe ./cmd/sentinel

.PHONY: build-windows-arm64
build-windows-arm64:
	GOOS=windows GOARCH=arm64 garble -literals -tiny -seed=random build \
		-ldflags "$(LDFLAGS)" -o bin/sentinel-windows-arm64.exe ./cmd/sentinel

.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-arm64 \
           build-windows-amd64 build-windows-arm64

# ── Utility ──────────────────────────────────────────────────

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: deps
deps:
	go mod tidy
```

### Garble Flags

| Flag | Purpose |
|---|---|
| `-literals` | Obfuscate string literals. **Critical** — hides the embedded public key PEM, error messages, and API paths in the binary. |
| `-tiny` | Strip file names, line numbers, and other debug info. Reduces binary size and makes stack traces opaque. |
| `-seed=random` | Randomize obfuscation seed per build. Prevents pattern recognition across builds. |

### Build Usage

**Dev build** (no obfuscation, fast):
```bash
make build ORG_PUBLIC_KEY_PEM="$(cat key.pem)"
```

**Production build for a specific org**:
```bash
make build-prod ORG_PUBLIC_KEY_PEM="$(cat /path/to/org_public_key.pem)" VERSION="1.0.0"
```

**All platforms**:
```bash
make build-all ORG_PUBLIC_KEY_PEM="$(cat key.pem)" VERSION="1.0.0"
```

### Garble Installation

Garble is a build tool, not a library dependency. Install it separately:

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

- [ ] `isDebuggerAttached()` returns false in normal execution
- [ ] `isDebuggerAttached()` returns true when a debugger is attached (manual test)
- [ ] Degradation stages progress over time after detection
- [ ] `StageWarnings`: warning messages appear on stderr
- [ ] `StageErrors`: IPC responses are intermittently corrupted/missing
- [ ] `StageSlowdown`: CPU and memory usage visibly increase
- [ ] `StageCrash`: process exits with a plausible error after delay
- [ ] Anti-tamper monitor runs with random jitter (not predictable interval)
- [ ] `make build` produces a working binary with embedded public key
- [ ] `make build-prod` produces a garble-obfuscated binary
- [ ] `make build-all` produces binaries for all 5 platforms
- [ ] Garble `-literals` flag hides string literals (verify with `strings` command)
- [ ] `garble` tool installation documented ← user action required
