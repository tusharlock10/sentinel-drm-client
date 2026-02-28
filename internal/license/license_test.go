package license

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tusharlock10/sentinel-drm-client/internal/crypto"
)

// writeLicFile signs payload with privKey and writes a .lic JSON file to a temp path.
// The caller is responsible for os.Remove on the returned path.
func writeLicFile(t *testing.T, payload map[string]any, privKey *ecdsa.PrivateKey) string {
	t.Helper()

	canonical, err := crypto.CanonicalJSON(payload)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	payloadB64 := crypto.Base64URLEncode(canonical)

	sigBytes, err := crypto.SignECDSA(privKey, []byte(payloadB64))
	if err != nil {
		t.Fatalf("SignECDSA: %v", err)
	}

	envelope := map[string]string{
		"alg":     "ES256",
		"payload": payloadB64,
		"sig":     crypto.Base64URLEncode(sigBytes),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	f, err := os.CreateTemp("", "test-*.lic")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// makeStandardPayload returns a minimal valid STANDARD payload for today.
func makeStandardPayload() map[string]any {
	today := time.Now().UTC()
	return map[string]any{
		"v":                           1,
		"license_key":                 "SENTINEL-A3RV-7MN2-KP8W-4GTH",
		"org_id":                      "11111111-1111-1111-1111-111111111111",
		"software_id":                 "22222222-2222-2222-2222-222222222222",
		"license_type":                "STANDARD",
		"issue_date":                  today.Format("2006-01-02"),
		"expiry_date":                 today.AddDate(1, 0, 0).Format("2006-01-02"),
		"max_machines":                10,
		"features":                    map[string]any{"max_users": 500},
		"server_url":                 "https://drm.example.com",
		"heartbeat_interval_minutes": 15,
	}
}

// makeHardwarePayload returns a minimal valid HARDWARE_BOUND payload for today.
func makeHardwarePayload() map[string]any {
	today := time.Now().UTC()
	return map[string]any{
		"v":                    1,
		"license_key":          "SENTINEL-A3RV-7MN2-KP8W-4GTH",
		"org_id":               "11111111-1111-1111-1111-111111111111",
		"software_id":          "22222222-2222-2222-2222-222222222222",
		"license_type":         "HARDWARE_BOUND",
		"issue_date":           today.Format("2006-01-02"),
		"expiry_date":          today.AddDate(1, 0, 0).Format("2006-01-02"),
		"max_machines":         1,
		"features":             map[string]any{},
		"hardware_fingerprint": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}
}

// --- Tests ------------------------------------------------------------------

func TestLoadAndVerifyStandard(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	path := writeLicFile(t, makeStandardPayload(), priv)
	defer os.Remove(path)

	payload, err := LoadAndVerify(path, &priv.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload.LicenseType != LicenseTypeStandard {
		t.Fatalf("expected STANDARD, got %s", payload.LicenseType)
	}
	if *payload.ServerURL != "https://drm.example.com" {
		t.Fatalf("unexpected server_url: %s", *payload.ServerURL)
	}
}

func TestLoadAndVerifyHardwareBound(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	path := writeLicFile(t, makeHardwarePayload(), priv)
	defer os.Remove(path)

	payload, err := LoadAndVerify(path, &priv.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload.LicenseType != LicenseTypeHardwareBound {
		t.Fatalf("expected HARDWARE_BOUND, got %s", payload.LicenseType)
	}
	if *payload.HardwareFingerprint == "" {
		t.Fatal("expected non-empty hardware_fingerprint")
	}
}

func TestLoadAndVerifyWrongKey(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	wrongKey, _ := crypto.GenerateECKeyPair()
	path := writeLicFile(t, makeStandardPayload(), priv)
	defer os.Remove(path)

	_, err := LoadAndVerify(path, &wrongKey.PublicKey)
	if err == nil {
		t.Fatal("expected error when verifying with wrong key, got nil")
	}
}

func TestLoadAndVerifyTamperedPayload(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()

	payload := makeStandardPayload()
	canonical, _ := crypto.CanonicalJSON(payload)
	payloadB64 := crypto.Base64URLEncode(canonical)
	sigBytes, _ := crypto.SignECDSA(priv, []byte(payloadB64))

	// Tamper: re-encode a different payload but keep the original signature.
	tamperedPayload := makeStandardPayload()
	tamperedPayload["max_machines"] = 9999
	tamperedCanonical, _ := crypto.CanonicalJSON(tamperedPayload)
	tamperedB64 := crypto.Base64URLEncode(tamperedCanonical)

	envelope := map[string]string{
		"alg":     "ES256",
		"payload": tamperedB64,
		"sig":     crypto.Base64URLEncode(sigBytes),
	}
	data, _ := json.Marshal(envelope)
	f, _ := os.CreateTemp("", "tampered-*.lic")
	f.Write(data)
	f.Close()
	defer os.Remove(f.Name())

	_, err := LoadAndVerify(f.Name(), &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for tampered payload, got nil")
	}
}

func TestLoadAndVerifyExpiredLicense(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	payload := makeStandardPayload()
	payload["expiry_date"] = time.Now().UTC().AddDate(-1, 0, 0).Format("2006-01-02")
	path := writeLicFile(t, payload, priv)
	defer os.Remove(path)

	_, err := LoadAndVerify(path, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for expired license, got nil")
	}
}

func TestLoadAndVerifyDormantLicense(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	payload := makeStandardPayload()
	payload["issue_date"] = time.Now().UTC().AddDate(0, 0, 7).Format("2006-01-02")
	payload["expiry_date"] = time.Now().UTC().AddDate(1, 0, 7).Format("2006-01-02")
	path := writeLicFile(t, payload, priv)
	defer os.Remove(path)

	_, err := LoadAndVerify(path, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for dormant license, got nil")
	}
}

func TestLoadAndVerifyUnknownLicenseType(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	payload := makeStandardPayload()
	payload["license_type"] = "UNKNOWN_TYPE"
	path := writeLicFile(t, payload, priv)
	defer os.Remove(path)

	_, err := LoadAndVerify(path, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for unknown license_type, got nil")
	}
}

func TestLoadAndVerifyStandardMissingServerURL(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	payload := makeStandardPayload()
	delete(payload, "server_url")
	path := writeLicFile(t, payload, priv)
	defer os.Remove(path)

	_, err := LoadAndVerify(path, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for missing server_url, got nil")
	}
}

func TestLoadAndVerifyStandardMissingHeartbeatInterval(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()

	payload := makeStandardPayload()
	delete(payload, "heartbeat_interval_minutes")
	path := writeLicFile(t, payload, priv)
	defer os.Remove(path)

	_, err := LoadAndVerify(path, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for missing heartbeat_interval_minutes, got nil")
	}
}

func TestLoadAndVerifyHardwareBoundMissingFingerprint(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	payload := makeHardwarePayload()
	delete(payload, "hardware_fingerprint")
	path := writeLicFile(t, payload, priv)
	defer os.Remove(path)

	_, err := LoadAndVerify(path, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for missing hardware_fingerprint, got nil")
	}
}

func TestLoadAndVerifyFileNotFound(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	_, err := LoadAndVerify("/nonexistent/path/license.lic", &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadAndVerifyWrongAlgorithm(t *testing.T) {
	priv, _ := crypto.GenerateECKeyPair()
	payload := makeStandardPayload()
	canonical, _ := crypto.CanonicalJSON(payload)
	payloadB64 := crypto.Base64URLEncode(canonical)
	sigBytes, _ := crypto.SignECDSA(priv, []byte(payloadB64))

	envelope := map[string]string{
		"alg":     "RS256",
		"payload": payloadB64,
		"sig":     crypto.Base64URLEncode(sigBytes),
	}
	data, _ := json.Marshal(envelope)
	f, _ := os.CreateTemp("", "wrongalg-*.lic")
	f.Write(data)
	f.Close()
	defer os.Remove(f.Name())

	_, err := LoadAndVerify(f.Name(), &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for wrong algorithm, got nil")
	}
}

func TestIsExpiredPastDate(t *testing.T) {
	p := &LicensePayload{ExpiryDate: time.Now().UTC().AddDate(-1, 0, 0).Format("2006-01-02")}
	if !IsExpired(p) {
		t.Fatal("expected expired=true for past expiry date")
	}
}

func TestIsExpiredFutureDate(t *testing.T) {
	p := &LicensePayload{ExpiryDate: time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02")}
	if IsExpired(p) {
		t.Fatal("expected expired=false for future expiry date")
	}
}

func TestIsExpiredToday(t *testing.T) {
	// A license expiring today is still valid (today is the last valid day).
	p := &LicensePayload{ExpiryDate: time.Now().UTC().Format("2006-01-02")}
	if IsExpired(p) {
		t.Fatal("expected expired=false for license expiring today")
	}
}

func TestIsExpiredUnparseable(t *testing.T) {
	p := &LicensePayload{ExpiryDate: "not-a-date"}
	if !IsExpired(p) {
		t.Fatal("expected expired=true for unparseable expiry date")
	}
}
