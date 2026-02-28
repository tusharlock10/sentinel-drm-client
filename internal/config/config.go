package config

import (
	"errors"
	"fmt"
	"os"
)

type Config struct {
	LicensePath  string
	SoftwarePath string
	Version      string // set from ldflags at build time; empty in dev builds
}

// Validate checks that all required paths exist on disk.
// Fails fast on the first error.
func (c *Config) Validate() error {
	if c.LicensePath == "" {
		return errors.New("license path is required")
	}
	if _, err := os.Stat(c.LicensePath); err != nil {
		return fmt.Errorf("license file not found: %w", err)
	}

	if c.SoftwarePath == "" {
		return errors.New("software path is required")
	}
	if _, err := os.Stat(c.SoftwarePath); err != nil {
		return fmt.Errorf("software binary not found: %w", err)
	}

	return nil
}
