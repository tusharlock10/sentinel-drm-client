//go:build linux

package hardware

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func getCPUSerial() (string, error) {
	// Primary: DMI product UUID (x86, most VMs and bare-metal)
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		val := strings.TrimSpace(string(data))
		if val != "" {
			return val, nil
		}
	}

	// Fallback: /proc/cpuinfo Serial field (ARM / embedded)
	data, err = os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", errors.New("cannot read CPU identifier: /sys/class/dmi/id/product_uuid and /proc/cpuinfo both unavailable")
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Serial") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" {
					return val, nil
				}
			}
		}
	}
	return "", errors.New("CPU serial not found in /proc/cpuinfo")
}

func getDiskSerial() (string, error) {
	out, err := exec.Command("findmnt", "-n", "-o", "SOURCE", "/").Output()
	if err != nil {
		return "", fmt.Errorf("findmnt failed: %w", err)
	}
	device := strings.TrimSpace(string(out))

	// Strip /dev/ prefix and partition suffix to get the base device name.
	// e.g. /dev/sda1 → sda, /dev/nvme0n1p1 → nvme0n1
	base := filepath.Base(device)
	base = strings.TrimRight(base, "0123456789")
	base = strings.TrimSuffix(base, "p") // nvme0n1p → nvme0n1

	serial, err := os.ReadFile(fmt.Sprintf("/sys/block/%s/serial", base))
	if err != nil {
		return "", fmt.Errorf("cannot read disk serial for %s: %w", base, err)
	}
	val := strings.TrimSpace(string(serial))
	if val == "" {
		return "", fmt.Errorf("empty disk serial for %s", base)
	}
	return val, nil
}

func getMachineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", fmt.Errorf("cannot read /etc/machine-id: %w", err)
	}
	val := strings.TrimSpace(string(data))
	if val == "" {
		return "", errors.New("/etc/machine-id is empty")
	}
	return val, nil
}
