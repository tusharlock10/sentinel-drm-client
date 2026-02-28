//go:build windows

package process

// Stop kills the child process directly.
// Windows does not support SIGTERM; processes are always hard-killed.
func (m *Manager) Stop() error {
	m.mu.Lock()
	if m.cmd.Process != nil {
		m.cmd.Process.Kill() //nolint:errcheck
	}
	m.mu.Unlock()
	<-m.exited
	return m.exitErr
}
