//go:build windows

package ipc

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

func dialSocket(socketPath string) (net.Conn, error) {
	timeout := 2 * time.Second
	return winio.DialPipe(socketPath, &timeout)
}
