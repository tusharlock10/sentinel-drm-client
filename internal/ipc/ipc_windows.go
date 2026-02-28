//go:build windows

package ipc

import (
	"net"

	"github.com/Microsoft/go-winio"
)

func newListener(socketPath string) (net.Listener, error) {
	return winio.ListenPipe(socketPath, nil)
}

func cleanupListener(_ string) {
	// Named pipes are automatically cleaned up when the listener is closed.
}
