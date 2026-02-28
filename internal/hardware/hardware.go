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

