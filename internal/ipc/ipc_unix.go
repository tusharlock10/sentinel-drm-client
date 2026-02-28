//go:build !windows

package ipc

import (
	"net"
	"os"
)

func newListener(socketPath string) (net.Listener, error) {
	os.Remove(socketPath) // remove stale socket file from a previous run
	return net.Listen("unix", socketPath)
}

func cleanupListener(socketPath string) {
	os.Remove(socketPath)
}
