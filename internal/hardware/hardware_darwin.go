//go:build darwin

package hardware

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func getCPUSerial() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("ioreg failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformSerialNumber") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				if val != "" {
					return val, nil
				}
			}
		}
	}
	return "", errors.New("IOPlatformSerialNumber not found in ioreg output")
}

func getDiskSerial() (string, error) {
	out, err := exec.Command("diskutil", "info", "/").Output()
	if err != nil {
		return "", fmt.Errorf("diskutil failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Volume UUID:") || strings.HasPrefix(trimmed, "Disk / Partition UUID:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" {
					return val, nil
				}
			}
		}
	}
	return "", errors.New("disk UUID not found in diskutil output")
}

func getMachineID() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("ioreg failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				if val != "" {
					return val, nil
				}
			}
		}
	}
	return "", errors.New("IOPlatformUUID not found in ioreg output")
}
