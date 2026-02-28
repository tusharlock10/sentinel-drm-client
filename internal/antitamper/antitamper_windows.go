//go:build windows

package antitamper

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                       = windows.NewLazyDLL("kernel32.dll")
	procIsDebuggerPresent          = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = kernel32.NewProc("CheckRemoteDebuggerPresent")
)

// isDebuggerAttached checks for both a local debugger (IsDebuggerPresent) and
// a remote debugger (CheckRemoteDebuggerPresent) attached to this process.
func isDebuggerAttached() bool {
	// Check for a local debugger (e.g. WinDbg, x64dbg attached locally).
	ret, _, _ := procIsDebuggerPresent.Call()
	if ret != 0 {
		return true
	}

	// Check for a remote debugger attached via the debug API.
	var isRemote int32
	ret, _, _ = procCheckRemoteDebuggerPresent.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&isRemote)),
	)
	if ret != 0 && isRemote != 0 {
		return true
	}

	return false
}
