//go:build !windows

package ipc

import "net"

func dialSocket(socketPath string) (net.Conn, error) {
	return net.Dial("unix", socketPath)
}
