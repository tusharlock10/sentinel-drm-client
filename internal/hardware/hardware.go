package hardware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// CollectFingerprint gathers hardware identifiers and returns
// SHA256Hex(cpuSerial + diskSerial + machineID).
func CollectFingerprint() (string, error) {
	cpu, err := getCPUSerial()
	if err != nil {
		return "", fmt.Errorf("collect CPU serial: %w", err)
	}
	disk, err := getDiskSerial()
	if err != nil {
		return "", fmt.Errorf("collect disk serial: %w", err)
	}
	mid, err := getMachineID()
	if err != nil {
		return "", fmt.Errorf("collect machine ID: %w", err)
	}

	sum := sha256.Sum256([]byte(cpu + disk + mid))
	return hex.EncodeToString(sum[:]), nil
}

// GetMachineID returns the platform-specific stable machine identifier.
// It is the same value used as one of the three inputs to CollectFingerprint.
// Used by the Phase 7 orchestrator to derive the keystore vault key.
func GetMachineID() (string, error) {
	id, err := getMachineID()
	if err != nil {
		return "", fmt.Errorf("collect machine ID: %w", err)
	}
	return id, nil
}
