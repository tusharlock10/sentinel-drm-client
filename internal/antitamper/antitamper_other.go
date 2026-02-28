//go:build !linux && !darwin && !windows

package antitamper

// isDebuggerAttached always returns false on unsupported platforms.
func isDebuggerAttached() bool {
	return false
}
