//go:build !windows

package process

import (
	"syscall"
	"time"
)

// Stop sends SIGTERM and waits up to 10 seconds for the process to exit gracefully.
// If it has not exited by then, SIGKILL is sent unconditionally.
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
