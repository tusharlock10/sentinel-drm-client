# Phase 6 — Process Management and IPC

**Status**: Pending
**Depends on**: Phase 1

---

## Goals

- Launch the licensed software binary as a child process and monitor its lifecycle.
- Serve license metadata to the running software over IPC (Unix domain socket on
  Linux/macOS, named pipes on Windows).
- Provide software binary checksum verification (ready but not enforced until backend
  adds `software_checksum` to the license payload).

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/process/process.go` | Created — launch, monitor, signal, stop |
| `internal/ipc/ipc.go` | Created — protocol definition, server logic, degrade hook |
| `internal/ipc/ipc_unix.go` | Created — Unix domain socket listener (Linux/macOS) |
| `internal/ipc/ipc_windows.go` | Created — Named pipe listener (Windows) |

---

## Process Management — `internal/process/process.go`

### Manager Struct

```go
type Manager struct {
    cmd     *exec.Cmd
    exited  chan struct{}
    exitErr error
    mu      sync.Mutex
}
```

### `Launch(binaryPath string, env []string) (*Manager, error)`

Launch the software binary as a child process.

```go
func Launch(binaryPath string, env []string) (*Manager, error) {
    cmd := exec.Command(binaryPath)
    cmd.Env = append(os.Environ(), env...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Start(); err != nil {
        return nil, fmt.Errorf("launch software: %w", err)
    }

    m := &Manager{
        cmd:    cmd,
        exited: make(chan struct{}),
    }

    go func() {
        m.exitErr = cmd.Wait()
        close(m.exited)
    }()

    return m, nil
}
```

**Environment variables passed to the software:**
- All existing environment variables (inherited via `os.Environ()`)
- `SENTINEL_IPC_SOCKET` — path to the IPC socket/pipe. The software reads this
  to connect back to Sentinel for license metadata queries.

`Stdout` and `Stderr` of the child are connected to Sentinel's own `Stdout`/`Stderr`
so the customer can see the software's output in the same terminal.

### `Wait() error`

Block until the child process exits. Returns the exit error (nil if exit code 0).

```go
func (m *Manager) Wait() error {
    <-m.exited
    return m.exitErr
}
```

### `Exited() <-chan struct{}`

Returns a channel that is closed when the process exits. Used by the orchestrator
to select on process exit alongside other events.

```go
func (m *Manager) Exited() <-chan struct{} {
    return m.exited
}
```

### `Signal(sig os.Signal)`

Send a signal to the child process.

```go
func (m *Manager) Signal(sig os.Signal) {
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.cmd.Process != nil {
        m.cmd.Process.Signal(sig)
    }
}
```

### `Stop() error`

Graceful shutdown: send SIGTERM, wait up to 10 seconds, then SIGKILL.

```go
func (m *Manager) Stop() error {
    m.Signal(syscall.SIGTERM)

    select {
    case <-m.exited:
        return m.exitErr
    case <-time.After(10 * time.Second):
        m.Signal(syscall.SIGKILL)
        <-m.exited
        return m.exitErr
    }
}
```

On Windows, `SIGTERM` doesn't exist. Use `cmd.Process.Kill()` directly as the
graceful shutdown mechanism (Windows processes handle `WM_CLOSE` or
`GenerateConsoleCtrlEvent` for Ctrl+C — but for simplicity, just kill).

### Software Binary Checksum Verification

```go
func VerifyBinaryChecksum(binaryPath string, expectedChecksum string) error {
    actual, err := crypto.SHA256File(binaryPath)
    if err != nil {
        return fmt.Errorf("compute binary checksum: %w", err)
    }
    if actual != expectedChecksum {
        return fmt.Errorf("binary checksum mismatch: expected %s, got %s", expectedChecksum, actual)
    }
    return nil
}
```

**Note**: This function is implemented now but not called until the backend adds a
`software_checksum` field to the license payload. The orchestrator (Phase 7) will
call it conditionally when the field is present.

---

## IPC — `internal/ipc/`

### Protocol

JSON-over-newline. Each message is a single JSON object terminated by `\n`.
The software connects to the socket, sends a request line, and receives a response line.

### Types — `ipc.go`

```go
// DegradeStage controls IPC response degradation for anti-tamper (Phase 8)
type DegradeStage int

const (
    StageNormal   DegradeStage = iota
    StageWarnings
    StageErrors
    StageSlowdown
    StageCrash
)

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

### Supported Methods

| Method | Response |
|---|---|
| `"get_license"` | Full license info: `{status: "ok", license: {...}}` |
| `"get_features"` | Features only: `{status: "ok", features: {...}}` |
| `"health"` | Liveness check: `{status: "ok"}` |

Unknown methods return: `{status: "error", error: "unknown method: xyz"}`.

### Server — `ipc.go`

```go
type Server struct {
    listener    net.Listener
    licenseInfo *LicenseInfo
    degradeStage atomic.Int32 // DegradeStage cast to int32
    mu          sync.Mutex
}

func NewServer(socketPath string, info *LicenseInfo) (*Server, error)
func (s *Server) Serve(ctx context.Context) error
func (s *Server) Close() error
func (s *Server) SetDegradeStage(stage DegradeStage)
```

#### `NewServer`

Creates the listener (platform-specific, see below) and returns the server.
Does NOT start serving — call `Serve()` separately.

#### `Serve(ctx context.Context) error`

Accept loop. On each connection:
1. Spawn a goroutine to handle the connection.
2. Read JSON lines with `bufio.Scanner`.
3. For each line: unmarshal `Request`, build `Response`, marshal and write back.
4. Connection is kept open until the client disconnects or context is cancelled.

Only one connection is expected at a time (the managed software). Multiple
connections are accepted but each is independent.

```go
func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()
    scanner := bufio.NewScanner(conn)
    encoder := json.NewEncoder(conn)

    for scanner.Scan() {
        var req Request
        if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
            encoder.Encode(Response{Status: "error", Error: "malformed request"})
            continue
        }
        resp := s.handleRequest(req)
        encoder.Encode(resp)
    }
}
```

#### `handleRequest`

```go
func (s *Server) handleRequest(req Request) Response {
    stage := DegradeStage(s.degradeStage.Load())

    // In degradation mode, inject errors
    if stage >= StageErrors {
        if shouldInjectError(stage) {
            return Response{Status: "error", Error: randomSystemError()}
        }
    }

    switch req.Method {
    case "get_license":
        if stage >= StageErrors {
            // Return partial/corrupted license info
            return degradedLicenseResponse(s.licenseInfo, stage)
        }
        return Response{Status: "ok", License: s.licenseInfo}

    case "get_features":
        if stage >= StageErrors {
            return Response{Status: "ok", Features: degradedFeatures(s.licenseInfo.Features, stage)}
        }
        return Response{Status: "ok", Features: s.licenseInfo.Features}

    case "health":
        return Response{Status: "ok"}

    default:
        return Response{Status: "error", Error: fmt.Sprintf("unknown method: %s", req.Method)}
    }
}
```

The degradation logic is stubbed here and fully implemented in Phase 8.

#### `SetDegradeStage(stage DegradeStage)`

Called by the anti-tamper monitor (Phase 8) when tampering is detected.

```go
func (s *Server) SetDegradeStage(stage DegradeStage) {
    s.degradeStage.Store(int32(stage))
}
```

#### `Close()`

Closes the listener and cleans up the socket file (Unix) or pipe handle (Windows).

### IPC Socket Path

| OS | Path |
|---|---|
| Linux/macOS | `/tmp/sentinel-<machine_id>.sock` |
| Windows | `\\.\pipe\sentinel-<machine_id>` |

The `<machine_id>` is the machine's UUID from the state file, ensuring each
Sentinel instance has a unique socket.

### Unix Socket — `ipc_unix.go`

```go
//go:build !windows

func newListener(socketPath string) (net.Listener, error) {
    // Remove stale socket file from previous run
    os.Remove(socketPath)
    return net.Listen("unix", socketPath)
}

func cleanupListener(socketPath string) {
    os.Remove(socketPath)
}
```

### Named Pipe — `ipc_windows.go`

```go
//go:build windows

func newListener(socketPath string) (net.Listener, error) {
    // Use winio for named pipe listener
    // socketPath is already in \\.\pipe\ format
    return winio.ListenPipe(socketPath, nil)
}

func cleanupListener(socketPath string) {
    // Named pipes are automatically cleaned up on Windows
}
```

**Note on Windows named pipes**: The `github.com/microsoft/go-winio` package
provides named pipe support. This is a Windows-only dependency (build-tagged).
If the dependency is too heavy, an alternative is to use a TCP listener on
`127.0.0.1:<random port>` on Windows only. This should be discussed with the user.

---

## Done Criteria

- [ ] `Launch` starts a child process and connects its stdout/stderr
- [ ] `Wait` blocks until the child exits
- [ ] `Exited()` channel closes when the child exits
- [ ] `Stop` sends SIGTERM, waits 10s, then SIGKILL
- [ ] `SENTINEL_IPC_SOCKET` env var is set in the child's environment
- [ ] `VerifyBinaryChecksum` computes correct SHA-256 and compares
- [ ] IPC server accepts connections on Unix domain socket (Linux/macOS)
- [ ] IPC `get_license` returns full license info
- [ ] IPC `get_features` returns features map
- [ ] IPC `health` returns ok
- [ ] IPC unknown method returns error
- [ ] IPC `SetDegradeStage` changes response behavior (stub for Phase 8)
- [ ] Socket file is cleaned up on server close
