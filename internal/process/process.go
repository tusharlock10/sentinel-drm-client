package process

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/tusharlock10/sentinel-drm-client/internal/crypto"
)

// Manager monitors the lifecycle of the launched software process.
type Manager struct {
	cmd     *exec.Cmd
	exited  chan struct{}
	exitErr error
	mu      sync.Mutex
}

// Launch starts the software binary as a child process. env contains additional
// environment variables (e.g. SENTINEL_IPC_SOCKET) appended to the current environment.
// The child's stdout and stderr are connected to the sentinel process's own output.
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

// Wait blocks until the child process exits and returns its exit error (nil for exit code 0).
func (m *Manager) Wait() error {
	<-m.exited
	return m.exitErr
}

// Exited returns a channel that is closed when the process exits.
// Use in a select alongside other events (heartbeat failure, OS signal, etc.).
func (m *Manager) Exited() <-chan struct{} {
	return m.exited
}

// Signal sends an OS signal to the child process.
func (m *Manager) Signal(sig os.Signal) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd.Process != nil {
		m.cmd.Process.Signal(sig) //nolint:errcheck
	}
}

// VerifyBinaryChecksum checks that the SHA-256 digest of the file at binaryPath matches
// expectedChecksum (hex string). Called before Launch when the license payload includes
// a software_checksum field.
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
