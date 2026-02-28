//go:build windows

package hardware

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// psQuery runs a PowerShell command and returns the trimmed stdout.
// Uses -NoProfile and -NonInteractive for speed and predictability.
// wmic is deprecated/removed on Windows 11; Get-CimInstance is the replacement.
func psQuery(command string) (string, error) {
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command", command,
	).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func getCPUSerial() (string, error) {
	val, err := psQuery("(Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1).ProcessorId")
	if err != nil {
		return "", fmt.Errorf("PowerShell Win32_Processor query failed: %w", err)
	}
	if val == "" {
		return "", errors.New("ProcessorId is empty")
	}
	return val, nil
}

func getDiskSerial() (string, error) {
	val, err := psQuery("(Get-CimInstance -ClassName Win32_DiskDrive -Filter 'Index=0' | Select-Object -First 1).SerialNumber")
	if err != nil {
		return "", fmt.Errorf("PowerShell Win32_DiskDrive query failed: %w", err)
	}
	if val == "" {
		return "", errors.New("disk SerialNumber is empty")
	}
	return val, nil
}

func getMachineID() (string, error) {
	val, err := psQuery("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid")
	if err != nil {
		return "", fmt.Errorf("PowerShell registry query failed: %w", err)
	}
	if val == "" {
		return "", errors.New("MachineGuid is empty")
	}
	return val, nil
}
