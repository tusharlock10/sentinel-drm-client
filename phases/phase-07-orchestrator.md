# Phase 7 — Main Orchestrator

**Status**: Pending
**Depends on**: Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, Phase 6

---

## Goals

- Wire all components together into the main `Sentinel` orchestrator.
- Implement the full STANDARD license flow (activation → heartbeat loop → grace period).
- Implement the full HARDWARE_BOUND license flow (offline fingerprint verification).
- Handle graceful shutdown on SIGINT/SIGTERM.

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/sentinel/sentinel.go` | Created — main orchestrator |
| `cmd/sentinel/main.go` | Modified — call `sentinel.New()` and `sentinel.Run()` |

---

## Orchestrator Struct

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

func New(cfg *config.Config, orgPubKey *ecdsa.PublicKey) *Sentinel
func (s *Sentinel) Run(ctx context.Context) error
```

---

## `Run(ctx context.Context) error`

The main entry point. Determines the license type and delegates to the appropriate flow.

```go
func (s *Sentinel) Run(ctx context.Context) error {
    // 1. Load and verify license
    lic, err := license.LoadAndVerify(s.config.LicensePath, s.orgPubKey)
    if err != nil {
        return fmt.Errorf("license verification failed: %w", err)
    }
    s.license = lic

    // 2. Branch based on license type
    switch lic.LicenseType {
    case license.LicenseTypeStandard:
        return s.runStandard(ctx)
    case license.LicenseTypeHardwareBound:
        return s.runHardwareBound(ctx)
    default:
        return fmt.Errorf("unsupported license type: %s", lic.LicenseType)
    }
}
```

---

## STANDARD License Flow — `runStandard(ctx)`

### Step 1: Validate Server URL

`config.ServerURL` is required for STANDARD licenses. If empty, exit with error:
`"--server-url is required for STANDARD licenses"`.

### Step 2: Initialize Keystore

```go
ks := keystore.New()
```

### Step 3: Load or Generate Machine Keypair

```go
privPEM, err := ks.Retrieve(keystore.KeyMachinePrivateKey)
if err != nil {
    // First run or keystore cleared — generate new keypair
    privKey, err := crypto.GenerateECKeyPair()
    privPEM, err = crypto.ECPrivateKeyToPEM(privKey)
    ks.Store(keystore.KeyMachinePrivateKey, privPEM)
}
machineKey, err := crypto.ParseECPrivateKeyPEM(privPEM)
machinePublicPEM, err := crypto.ECPublicKeyToPEM(&machineKey.PublicKey)
```

Use `memguard` to protect the private key bytes in memory (wrap in a `LockedBuffer`
that prevents the memory from being swapped to disk or appearing in core dumps).

### Step 4: Load or Create State

```go
stateMgr, err := state.NewStateManager(ks)
st, err := stateMgr.Load()

if st == nil {
    // First run
    st = &state.State{
        MachineID:             uuid.New().String(),
        Activated:             false,
        LicenseKey:            s.license.LicenseKey,
        GraceRemainingSeconds: int64(*s.license.HeartbeatGracePeriodDays) * 86400,
    }
    stateMgr.Save(st)
}
```

### Step 5: License Key Change Detection

```go
if st.LicenseKey != s.license.LicenseKey {
    // User switched license file — reset activation state
    st.Activated = false
    st.LicenseKey = s.license.LicenseKey
    st.GraceRemainingSeconds = int64(*s.license.HeartbeatGracePeriodDays) * 86400
    st.GraceExhausted = false
    stateMgr.Save(st)
}
```

### Step 6: Create DRM Client

```go
drmClient := drm.NewClient(s.config.ServerURL, st.MachineID, machineKey, s.orgPubKey)
```

### Step 7: Activation (if needed)

```go
if !st.Activated {
    resp, err := drmClient.Activate(drm.ActivateRequest{
        LicenseKey:          s.license.LicenseKey,
        MachineID:           st.MachineID,
        MachinePublicKeyPEM: machinePublicPEM,
        Platform:            drm.DetectPlatform(),
        SoftwareVersion:     version, // embedded build var
    })
    if err != nil {
        return fmt.Errorf("activation failed: %w", err)
    }
    st.Activated = true
    st.LastHeartbeatSuccess = time.Now().Unix()
    stateMgr.Save(st)
}
```

If activation fails with a server error (not a connection error), exit immediately
with the error message (e.g., "Maximum machine limit reached for this license.").

### Step 8: Mandatory Startup Heartbeat

STANDARD licenses MUST contact the server on every startup. This prevents grace
period abuse (restart cycling to avoid heartbeat checks).

```go
resp, err := drmClient.Heartbeat(drm.HeartbeatRequest{
    LicenseKey:      s.license.LicenseKey,
    MachineID:       st.MachineID,
    SoftwareVersion: version,
})

if err != nil {
    if drm.IsConnectionError(err) {
        // Server unreachable — check grace
        if st.GraceExhausted {
            return errors.New("server unreachable and grace period exhausted — cannot start")
        }
        if st.GraceRemainingSeconds <= 0 {
            st.GraceExhausted = true
            stateMgr.Save(st)
            return errors.New("server unreachable and grace period exhausted — cannot start")
        }
        // Grace available — allow startup, will consume during heartbeat loop
        log.Printf("WARNING: Server unreachable, operating under grace period (%d seconds remaining)",
            st.GraceRemainingSeconds)
    } else {
        return fmt.Errorf("startup heartbeat failed: %w", err)
    }
} else {
    // Process heartbeat response
    if err := s.processHeartbeatResponse(resp, st, stateMgr, drmClient); err != nil {
        return err
    }
}
```

### Step 9: Launch Software

```go
ipcSocketPath := ipc.SocketPath(st.MachineID)
env := []string{
    fmt.Sprintf("SENTINEL_IPC_SOCKET=%s", ipcSocketPath),
}

proc, err := process.Launch(s.config.SoftwarePath, env)
if err != nil {
    return fmt.Errorf("launch software: %w", err)
}
s.process = proc
```

### Step 10: Start IPC Server

```go
licenseInfo := &ipc.LicenseInfo{
    LicenseKey:  s.license.LicenseKey,
    LicenseType: string(s.license.LicenseType),
    ExpiryDate:  s.license.ExpiryDate,
    Features:    s.license.Features,
    OrgID:       s.license.OrgID,
    SoftwareID:  s.license.SoftwareID,
}
ipcSrv, err := ipc.NewServer(ipcSocketPath, licenseInfo)
s.ipcServer = ipcSrv

go ipcSrv.Serve(ctx)
```

### Step 11: Start Heartbeat Loop

```go
go s.heartbeatLoop(ctx, st, stateMgr, drmClient)
```

### Step 12: Wait for Exit

```go
select {
case <-proc.Exited():
    // Software process exited — shut down everything
    s.cleanup(ctx, st, stateMgr)
    return proc.Wait()

case <-ctx.Done():
    // Signal received — graceful shutdown
    s.cleanup(ctx, st, stateMgr)
    proc.Stop()
    return nil
}
```

---

## Heartbeat Loop

```go
func (s *Sentinel) heartbeatLoop(ctx context.Context, st *state.State, stateMgr *state.StateManager, drmClient *drm.Client) {
    interval := time.Duration(*s.license.HeartbeatIntervalMinutes) * time.Minute
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            resp, err := drmClient.Heartbeat(drm.HeartbeatRequest{
                LicenseKey:      s.license.LicenseKey,
                MachineID:       st.MachineID,
                SoftwareVersion: version,
            })

            if err != nil {
                if drm.IsConnectionError(err) {
                    s.consumeGrace(st, stateMgr, interval)
                    if s.isGraceExhausted(st) {
                        log.Println("Grace period exhausted — shutting down")
                        s.process.Stop()
                        return
                    }
                    log.Printf("Heartbeat failed (connection error), grace remaining: %ds", st.GraceRemainingSeconds)
                } else {
                    log.Printf("Heartbeat error: %v", err)
                    // Server responded with an error — don't consume grace
                    // Could be a temporary issue, retry next interval
                }
                continue
            }

            // Successful heartbeat
            st.LastHeartbeatSuccess = time.Now().Unix()
            stateMgr.Save(st)

            if err := s.processHeartbeatResponse(resp, st, stateMgr, drmClient); err != nil {
                s.process.Stop()
                return
            }
        }
    }
}
```

---

## Grace Period Logic

### `consumeGrace`

```go
func (s *Sentinel) consumeGrace(st *state.State, stateMgr *state.StateManager, interval time.Duration) {
    consumed := int64(interval.Seconds())
    st.GraceRemainingSeconds -= consumed
    if st.GraceRemainingSeconds < 0 {
        st.GraceRemainingSeconds = 0
    }
    if st.GraceRemainingSeconds == 0 {
        st.GraceExhausted = true
    }
    stateMgr.Save(st)
}
```

### `isGraceExhausted`

```go
func (s *Sentinel) isGraceExhausted(st *state.State) bool {
    if st.GraceExhausted {
        return true
    }
    return st.GraceRemainingSeconds <= 0
}
```

### Grace Rules (Summary)

1. **Total quota**: `heartbeat_grace_period_days * 86400` seconds.
2. **Each missed heartbeat**: consumes `heartbeat_interval_minutes * 60` seconds.
3. **Successful heartbeat**: stops consumption. Remaining quota is preserved, NOT reset.
4. **After full exhaustion** (`GraceExhausted = true`):
   - If software comes back online and heartbeat succeeds: software works.
   - But next single missed heartbeat = immediate shutdown (no grace left).
5. **Startup always contacts server**: prevents restart cycling to reset grace.
6. **Server is source of truth**: if server is reachable, grace is not consumed.

---

## Heartbeat Response Processing

```go
func (s *Sentinel) processHeartbeatResponse(resp *drm.HeartbeatResponse, st *state.State, stateMgr *state.StateManager, drmClient *drm.Client) error {
    switch resp.Status {
    case "ACTIVE":
        return nil // all good

    case "DECOMMISSION_PENDING":
        log.Println("Decommission requested — acknowledging and shutting down")
        _, err := drmClient.DecommissionAck(drm.DecommissionAckRequest{
            LicenseKey: s.license.LicenseKey,
            MachineID:  st.MachineID,
        })
        if err != nil {
            log.Printf("Decommission ack failed: %v", err)
        }
        stateMgr.Delete()
        return fmt.Errorf("machine decommissioned")

    case "REVOKED":
        return fmt.Errorf("license has been revoked")

    case "EXPIRED":
        return fmt.Errorf("license has expired")

    case "SUSPENDED":
        return fmt.Errorf("license is suspended — contact your vendor")

    default:
        return fmt.Errorf("unexpected license status: %s", resp.Status)
    }
}
```

---

## HARDWARE_BOUND License Flow — `runHardwareBound(ctx)`

Simpler flow — no server communication, no heartbeats, no state file.

### Step 1: Collect Hardware Fingerprint

```go
fingerprint, err := hardware.CollectFingerprint()
if err != nil {
    return fmt.Errorf("hardware fingerprint collection failed: %w", err)
}
```

### Step 2: Compare Fingerprint

```go
if fingerprint != *s.license.HardwareFingerprint {
    return fmt.Errorf("hardware fingerprint mismatch: this license is not valid for this machine")
}
```

### Step 3: Launch Software

```go
machineID := fingerprint // use fingerprint as machine ID for socket naming
ipcSocketPath := ipc.SocketPath(machineID)
env := []string{
    fmt.Sprintf("SENTINEL_IPC_SOCKET=%s", ipcSocketPath),
}

proc, err := process.Launch(s.config.SoftwarePath, env)
```

### Step 4: Start IPC Server

Same as STANDARD flow.

### Step 5: Wait for Exit

```go
select {
case <-proc.Exited():
    ipcSrv.Close()
    return proc.Wait()
case <-ctx.Done():
    ipcSrv.Close()
    proc.Stop()
    return nil
}
```

No heartbeat loop. No grace period. Fully offline.

---

## Signal Handling

Setup in `Run()` before branching to license-type-specific flows.

```go
func (s *Sentinel) setupSignalHandler() (context.Context, context.CancelFunc) {
    ctx, cancel := context.WithCancel(context.Background())

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        sig := <-sigCh
        log.Printf("Received signal %v, shutting down...", sig)
        cancel()
    }()

    return ctx, cancel
}
```

### Cleanup Sequence

```go
func (s *Sentinel) cleanup(ctx context.Context, st *state.State, stateMgr *state.StateManager) {
    if s.ipcServer != nil {
        s.ipcServer.Close()
    }
    if st != nil && stateMgr != nil {
        stateMgr.Save(st)
    }
}
```

---

## Integration with `cmd/sentinel/main.go`

The main function is updated to call the orchestrator:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    // ... (validate embedded key, parse flags, validate config) ...

    s := sentinel.New(cfg, orgPubKey)
    ctx, cancel := s.setupSignalHandler()
    defer cancel()
    return s.Run(ctx)
},
```

---

## Done Criteria

- [ ] STANDARD flow: activation → heartbeat → software launch works end-to-end
- [ ] STANDARD flow: startup heartbeat is mandatory (fails without server)
- [ ] STANDARD flow: grace period allows startup when server is unreachable (if quota > 0)
- [ ] STANDARD flow: grace exhaustion causes shutdown
- [ ] STANDARD flow: `GraceExhausted = true` → next miss = immediate stop
- [ ] STANDARD flow: successful heartbeat preserves (not resets) grace remaining
- [ ] STANDARD flow: license key change triggers re-activation
- [ ] STANDARD flow: decommission response triggers ack and shutdown
- [ ] STANDARD flow: REVOKED/EXPIRED/SUSPENDED responses cause shutdown with message
- [ ] HARDWARE_BOUND flow: matching fingerprint → software launches
- [ ] HARDWARE_BOUND flow: mismatching fingerprint → exit with error
- [ ] HARDWARE_BOUND flow: no server communication attempted
- [ ] Signal handling: SIGINT/SIGTERM → graceful shutdown of IPC, process, state save
- [ ] Software process exit → Sentinel shuts down
- [ ] IPC socket path includes machine ID for uniqueness
