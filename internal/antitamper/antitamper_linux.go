//go:build linux

package antitamper

import (
	"os"
	"strings"
)

// isDebuggerAttached checks /proc/self/status for a non-zero TracerPid field,
// which indicates that a debugger (ptrace) is attached to this process.
func isDebuggerAttached() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false // cannot read, assume safe
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
		}
	}
	return false
}
