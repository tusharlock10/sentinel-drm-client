package antitamper

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/tusharlock10/sentinel-drm-client/internal/ipc"
)

// Monitor runs periodic debugger checks and drives the degradation state machine
// when tampering is detected.
type Monitor struct {
	ipcServer  *ipc.Server
	detected   atomic.Bool
	stage      atomic.Int32
	detectedAt time.Time
}

// NewMonitor creates a Monitor that will degrade ipcServer responses on detection.
func NewMonitor(ipcServer *ipc.Server) *Monitor {
	return &Monitor{ipcServer: ipcServer}
}

// Start runs the anti-tamper monitoring loop. It should be called in a goroutine.
// Returns when ctx is cancelled.
func (m *Monitor) Start(ctx context.Context) {
	// Check immediately at startup before entering the loop.
	if isDebuggerAttached() {
		m.onDetected(ctx)
	}

	for {
		// Random interval 5-10 seconds to prevent predictable timing fingerprinting.
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

// IsCompromised reports whether tampering has been detected.
func (m *Monitor) IsCompromised() bool {
	return m.detected.Load()
}

// onDetected is called on first detection. It sets the flag, records the time,
// advances to StageWarnings, and starts the warning emission goroutine.
func (m *Monitor) onDetected(ctx context.Context) {
	if m.detected.CompareAndSwap(false, true) {
		m.detectedAt = time.Now()
		m.stage.Store(int32(ipc.StageWarnings))
		m.ipcServer.SetDegradeStage(ipc.StageWarnings)
		go m.warningLoop(ctx)
	}
}

// progressDegradation advances the degradation stage based on time elapsed since
// detection. A ±30s jitter is applied so stage transitions are not predictable.
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

// applyStage triggers stage-specific side effects when a stage is first entered.
func (m *Monitor) applyStage(stage ipc.DegradeStage) {
	switch stage {
	case ipc.StageSlowdown:
		applySlowdown()
	case ipc.StageCrash:
		go triggerCrash()
	}
}

// ---------------------------------------------------------------------------
// Warning emission goroutine
// ---------------------------------------------------------------------------

// warningLoop runs in its own goroutine. It emits cryptic-looking messages to
// stderr every 15-30 seconds while tampering is detected. The messages escalate
// from warnings to errors as the stage advances.
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

// ---------------------------------------------------------------------------
// StageSlowdown — resource pressure
// ---------------------------------------------------------------------------

// applySlowdown starts goroutines that allocate memory and burn CPU to make the
// process appear unstable. These goroutines intentionally leak — that is the point.
func applySlowdown() {
	// Memory allocation goroutine: allocate 50 MB in 1 MB chunks.
	go func() {
		var waste [][]byte
		for i := 0; i < 50; i++ {
			chunk := make([]byte, 1<<20) // 1 MB
			_, _ = crand.Read(chunk)     // fill to prevent compiler optimization
			waste = append(waste, chunk)
			time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)
		}
		runtime.KeepAlive(waste)
	}()

	// CPU busy-loop goroutines: hash 4 KB buffers in a tight loop.
	for i := 0; i < 2; i++ {
		go func() {
			for {
				_ = sha256.Sum256(make([]byte, 4096))
				time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
			}
		}()
	}
}

// ---------------------------------------------------------------------------
// StageCrash — terminal failure
// ---------------------------------------------------------------------------

// triggerCrash waits a randomised delay then exits with exit code 137, which
// looks like an OOM kill (SIGKILL = 128 + 9), to obscure the true cause.
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
