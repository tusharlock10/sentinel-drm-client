package license

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tusharlock10/sentinel-drm-client/internal/crypto"
)

// LicenseEnvelope is the raw JSON structure of a .lic file.
type LicenseEnvelope struct {
	Alg     string `json:"alg"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// LicenseType identifies the kind of license.
type LicenseType string

const (
	LicenseTypeStandard      LicenseType = "STANDARD"
	LicenseTypeHardwareBound LicenseType = "HARDWARE_BOUND"
)

// LicensePayload is the decoded and verified content of a .lic file.
type LicensePayload struct {
	V           int            `json:"v"`
	LicenseKey  string         `json:"license_key"`
	OrgID       string         `json:"org_id"`
	SoftwareID  string         `json:"software_id"`
	LicenseType LicenseType    `json:"license_type"`
	IssueDate   string         `json:"issue_date"`  // "YYYY-MM-DD"
	ExpiryDate  string         `json:"expiry_date"` // "YYYY-MM-DD"
	MaxMachines int            `json:"max_machines"`
	Features    map[string]any `json:"features"`

	// STANDARD only
	ServerURL                *string `json:"server_url,omitempty"`
	HeartbeatIntervalMinutes *int    `json:"heartbeat_interval_minutes,omitempty"`

	// HARDWARE_BOUND only
	HardwareFingerprint *string `json:"hardware_fingerprint,omitempty"`
}

// LoadAndVerify reads a .lic file from disk, verifies its ECDSA signature against
// orgPubKey, validates the payload fields, and returns the decoded payload.
func LoadAndVerify(path string, orgPubKey *ecdsa.PublicKey) (*LicensePayload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("license file not found: %s", path)
	}

	var envelope LicenseEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("invalid license file: malformed JSON")
	}

	if envelope.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported license algorithm: %s (expected ES256)", envelope.Alg)
	}

	sigBytes, err := crypto.Base64URLDecode(envelope.Sig)
	if err != nil {
		return nil, fmt.Errorf("invalid license file: malformed signature encoding")
	}

	// Signature is over the raw base64url payload string bytes — NOT the decoded JSON.
	if err := crypto.VerifyECDSA(orgPubKey, []byte(envelope.Payload), sigBytes); err != nil {
		return nil, fmt.Errorf("license signature verification failed")
	}

	payloadBytes, err := crypto.Base64URLDecode(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid license file: malformed payload encoding")
	}

	var payload LicensePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid license payload: malformed JSON")
	}

	if err := validatePayload(&payload); err != nil {
		return nil, err
	}

	return &payload, nil
}

// validatePayload checks all required fields and type-specific constraints,
// including dormancy and expiry date checks.
func validatePayload(p *LicensePayload) error {
	if p.V != 1 {
		return fmt.Errorf("license version %d is not supported (expected 1)", p.V)
	}
	if p.LicenseKey == "" {
		return fmt.Errorf("invalid license payload: license_key is missing")
	}
	if p.OrgID == "" {
		return fmt.Errorf("invalid license payload: org_id is missing")
	}
	if p.SoftwareID == "" {
		return fmt.Errorf("invalid license payload: software_id is missing")
	}
	if p.LicenseType != LicenseTypeStandard && p.LicenseType != LicenseTypeHardwareBound {
		return fmt.Errorf("invalid license payload: unknown license_type %q", p.LicenseType)
	}
	if p.MaxMachines < 1 {
		return fmt.Errorf("invalid license payload: max_machines must be >= 1")
	}

	issueDate, err := time.Parse("2006-01-02", p.IssueDate)
	if err != nil {
		return fmt.Errorf("invalid license payload: malformed issue_date %q", p.IssueDate)
	}
	expiryDate, err := time.Parse("2006-01-02", p.ExpiryDate)
	if err != nil {
		return fmt.Errorf("invalid license payload: malformed expiry_date %q", p.ExpiryDate)
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)

	if today.Before(issueDate) {
		return fmt.Errorf("license is not yet active (activates: %s)", p.IssueDate)
	}
	if today.After(expiryDate) {
		return fmt.Errorf("license has expired (expiry: %s)", p.ExpiryDate)
	}

	switch p.LicenseType {
	case LicenseTypeStandard:
		if p.ServerURL == nil || *p.ServerURL == "" {
			return fmt.Errorf("STANDARD license missing server_url")
		}
		if p.HeartbeatIntervalMinutes == nil || *p.HeartbeatIntervalMinutes <= 0 {
			return fmt.Errorf("STANDARD license missing heartbeat_interval_minutes")
		}
		if p.HardwareFingerprint != nil && *p.HardwareFingerprint != "" {
			return fmt.Errorf("invalid license payload: hardware_fingerprint must not be set for STANDARD licenses")
		}

	case LicenseTypeHardwareBound:
		if p.HardwareFingerprint == nil || *p.HardwareFingerprint == "" {
			return fmt.Errorf("HARDWARE_BOUND license missing hardware_fingerprint")
		}
		if p.HeartbeatIntervalMinutes != nil {
			return fmt.Errorf("invalid license payload: heartbeat_interval_minutes must not be set for HARDWARE_BOUND licenses")
		}
	}

	return nil
}

// IsExpired reports whether the license has passed its expiry date.
// Used by the orchestrator during runtime (e.g., heartbeat loop may run past midnight).
func IsExpired(p *LicensePayload) bool {
	expiry, err := time.Parse("2006-01-02", p.ExpiryDate)
	if err != nil {
		return true // unparseable = treat as expired
	}
	return time.Now().UTC().Truncate(24 * time.Hour).After(expiry)
}
