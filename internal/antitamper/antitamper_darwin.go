//go:build darwin

package antitamper

import (
	"os"

	"golang.org/x/sys/unix"
)

// pTraced is the P_TRACED flag from <sys/proc.h>. Set by the kernel when a
// debugger is attached to the process. Not exported by golang.org/x/sys/unix.
const pTraced = 0x00000800

// isDebuggerAttached uses sysctl to query the kernel for our process info and
// checks the P_TRACED flag, which is set when a debugger is attached.
func isDebuggerAttached() bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return false // cannot determine, assume safe
	}
	return info.Proc.P_flag&pTraced != 0
}
