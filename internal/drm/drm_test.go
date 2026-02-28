package drm

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tusharlock10/sentinel-drm-client/internal/crypto"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// responseBuilder is called by the mock server to produce the signed response body.
// It receives the nonce from the request header so it can be reflected in the payload.
type responseBuilder func(nonce string, orgPrivKey *ecdsa.PrivateKey) []byte

// newMockServer starts a test HTTP server for a single DRM endpoint.
// It returns the client (configured to talk to the server) and the org private key
// (so tests can sign mock responses themselves when needed).
func newMockServer(t *testing.T, expectedPath string, buildResp responseBuilder) (*Client, *ecdsa.PrivateKey, *httptest.Server) {
	t.Helper()

	orgPrivKey, err := crypto.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate org keypair: %v", err)
	}
	machinePrivKey, err := crypto.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate machine keypair: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expectedPath {
			t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		nonce := r.Header.Get("X-Sentinel-Nonce")
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildResp(nonce, orgPrivKey))
	}))

	client := NewClient(ts.URL, "test-machine-id", machinePrivKey, &orgPrivKey.PublicKey)
	return client, orgPrivKey, ts
}

// signMockResponse builds a signed response envelope matching the backend's sign_response().
// payload must include "request_nonce" so the client's nonce check passes.
func signMockResponse(t *testing.T, payload map[string]any, orgPrivKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	canonical, err := crypto.CanonicalJSON(payload)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	payloadB64 := crypto.Base64URLEncode(canonical)

	sig, err := crypto.SignECDSA(orgPrivKey, []byte(payloadB64))
	if err != nil {
		t.Fatalf("SignECDSA: %v", err)
	}

	envelope := map[string]string{
		"payload": payloadB64,
		"sig":     crypto.Base64URLEncode(sig),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal mock response: %v", err)
	}
	return data
}

// activatePayload returns a valid activate response payload reflecting the given nonce.
func activatePayload(nonce string) map[string]any {
	return map[string]any{
		"status":                      "ACTIVE",
		"machine_id":                  "test-machine-id",
		"license_key":                 "SENTINEL-TEST-0001",
		"expiry_date":                 "2027-01-01",
		"heartbeat_interval_minutes":  15,
		"heartbeat_grace_period_days": 3,
		"features":                    map[string]any{"max_users": float64(500)},
		"request_nonce":               nonce,
		"responded_at":                time.Now().UTC().Format(time.RFC3339),
	}
}

func heartbeatPayload(nonce string) map[string]any {
	return map[string]any{
		"status":               "ACTIVE",
		"machine_id":           "test-machine-id",
		"license_key":          "SENTINEL-TEST-0001",
		"expiry_date":          "2027-01-01",
		"decommission_pending": false,
		"request_nonce":        nonce,
		"responded_at":         time.Now().UTC().Format(time.RFC3339),
	}
}

func decommissionPayload(nonce string) map[string]any {
	return map[string]any{
		"status":        "DECOMMISSIONED",
		"machine_id":    "test-machine-id",
		"license_key":   "SENTINEL-TEST-0001",
		"request_nonce": nonce,
		"responded_at":  time.Now().UTC().Format(time.RFC3339),
	}
}

// ---------------------------------------------------------------------------
// Endpoint success tests
// ---------------------------------------------------------------------------

func TestActivate_Success(t *testing.T) {
	client, orgPrivKey, ts := newMockServer(t, "/api/v1/drm/activate/", func(nonce string, orgPrivKey *ecdsa.PrivateKey) []byte {
		return signMockResponse(t, activatePayload(nonce), orgPrivKey)
	})
	defer ts.Close()
	_ = orgPrivKey

	resp, err := client.Activate(ActivateRequest{
		LicenseKey:          "SENTINEL-TEST-0001",
		MachineID:           "test-machine-id",
		MachinePublicKeyPEM: "pem-placeholder",
		Platform:            DetectPlatform(),
		SoftwareVersion:     "1.0.0",
	})
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if resp.Status != "ACTIVE" {
		t.Errorf("expected ACTIVE, got %s", resp.Status)
	}
	if resp.HeartbeatIntervalMinutes != 15 {
		t.Errorf("expected heartbeat_interval_minutes 15, got %d", resp.HeartbeatIntervalMinutes)
	}
	if resp.HeartbeatGracePeriodDays != 3 {
		t.Errorf("expected heartbeat_grace_period_days 3, got %d", resp.HeartbeatGracePeriodDays)
	}
	if resp.LicenseKey != "SENTINEL-TEST-0001" {
		t.Errorf("license_key mismatch: %s", resp.LicenseKey)
	}
}

func TestHeartbeat_Success(t *testing.T) {
	client, _, ts := newMockServer(t, "/api/v1/drm/heartbeat/", func(nonce string, orgPrivKey *ecdsa.PrivateKey) []byte {
		return signMockResponse(t, heartbeatPayload(nonce), orgPrivKey)
	})
	defer ts.Close()

	resp, err := client.Heartbeat(HeartbeatRequest{
		LicenseKey:      "SENTINEL-TEST-0001",
		MachineID:       "test-machine-id",
		SoftwareVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if resp.Status != "ACTIVE" {
		t.Errorf("expected ACTIVE, got %s", resp.Status)
	}
	if resp.DecommissionPending {
		t.Error("expected DecommissionPending=false")
	}
}

func TestDecommissionAck_Success(t *testing.T) {
	client, _, ts := newMockServer(t, "/api/v1/drm/decommission-ack/", func(nonce string, orgPrivKey *ecdsa.PrivateKey) []byte {
		return signMockResponse(t, decommissionPayload(nonce), orgPrivKey)
	})
	defer ts.Close()

	resp, err := client.DecommissionAck(DecommissionAckRequest{
		LicenseKey: "SENTINEL-TEST-0001",
		MachineID:  "test-machine-id",
	})
	if err != nil {
		t.Fatalf("DecommissionAck: %v", err)
	}
	if resp.Status != "DECOMMISSIONED" {
		t.Errorf("expected DECOMMISSIONED, got %s", resp.Status)
	}
}

// ---------------------------------------------------------------------------
// Request signing verification
// ---------------------------------------------------------------------------

// TestRequestSigning_SignatureVerifiedByServer has the mock server verify the
// incoming ECDSA signature and signing string format, exactly as the backend does.
func TestRequestSigning_SignatureVerifiedByServer(t *testing.T) {
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	machinePrivKey, _ := crypto.GenerateECKeyPair()
	machinePubKey := &machinePrivKey.PublicKey

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		machineID := r.Header.Get("X-Sentinel-Machine-Id")
		timestamp := r.Header.Get("X-Sentinel-Timestamp")
		nonce := r.Header.Get("X-Sentinel-Nonce")
		sigB64 := r.Header.Get("X-Sentinel-Signature")

		if machineID == "" || timestamp == "" || nonce == "" || sigB64 == "" {
			t.Error("missing required X-Sentinel-* headers")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Read and hash the request body (mirrors backend signing.py step 3).
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		bodyHash := crypto.SHA256Hex(body)

		// Reconstruct the signing string (must match buildSignedRequest exactly).
		signingString := fmt.Sprintf("POST\n%s\n%s\n%s\n%s", r.URL.Path, timestamp, nonce, bodyHash)

		sigBytes, err := crypto.Base64URLDecode(sigB64)
		if err != nil {
			t.Errorf("decode signature header: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := crypto.VerifyECDSA(machinePubKey, []byte(signingString), sigBytes); err != nil {
			t.Errorf("request signature verification failed: %v\nsigning_string:\n%s", err, signingString)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return a valid signed response.
		payload := heartbeatPayload(nonce)
		w.Header().Set("Content-Type", "application/json")
		w.Write(signMockResponse(t, payload, orgPrivKey))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-machine-id", machinePrivKey, &orgPrivKey.PublicKey)
	_, err := client.Heartbeat(HeartbeatRequest{
		LicenseKey:      "SENTINEL-TEST-0001",
		MachineID:       "test-machine-id",
		SoftwareVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Heartbeat (signing verification): %v", err)
	}
}

// ---------------------------------------------------------------------------
// Response verification error cases
// ---------------------------------------------------------------------------

func TestResponse_TamperedSignature(t *testing.T) {
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	wrongPrivKey, _ := crypto.GenerateECKeyPair()
	machinePrivKey, _ := crypto.GenerateECKeyPair()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("X-Sentinel-Nonce")
		// Sign with the wrong key — the client holds orgPrivKey's public key, so this fails.
		w.Header().Set("Content-Type", "application/json")
		w.Write(signMockResponse(t, heartbeatPayload(nonce), wrongPrivKey))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-machine-id", machinePrivKey, &orgPrivKey.PublicKey)
	_, err := client.Heartbeat(HeartbeatRequest{LicenseKey: "K", MachineID: "M"})
	if err == nil {
		t.Fatal("expected signature verification failure, got nil error")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestResponse_NonceMismatch(t *testing.T) {
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	machinePrivKey, _ := crypto.GenerateECKeyPair()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a correctly-signed response but with a stale/wrong nonce.
		stalPayload := heartbeatPayload("00000000-0000-0000-0000-000000000000")
		w.Header().Set("Content-Type", "application/json")
		w.Write(signMockResponse(t, stalPayload, orgPrivKey))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-machine-id", machinePrivKey, &orgPrivKey.PublicKey)
	_, err := client.Heartbeat(HeartbeatRequest{LicenseKey: "K", MachineID: "M"})
	if err == nil {
		t.Fatal("expected nonce mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "nonce mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Backend error response parsing
// ---------------------------------------------------------------------------

func TestBackendError_ParsedCorrectly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Maximum machine limit reached for this license."}`))
	}))
	defer ts.Close()

	machinePrivKey, _ := crypto.GenerateECKeyPair()
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	client := NewClient(ts.URL, "test-machine-id", machinePrivKey, &orgPrivKey.PublicKey)

	_, err := client.Activate(ActivateRequest{LicenseKey: "K", MachineID: "M"})
	if err == nil {
		t.Fatal("expected error for 400 response")
	}

	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apiError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Message, "Maximum machine limit") {
		t.Errorf("unexpected error message: %s", apiErr.Message)
	}
	// IsConnectionError must return false for server errors.
	if IsConnectionError(err) {
		t.Error("server 400 error should not be treated as a connection error")
	}
}

func TestBackendError_NonJSONBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer ts.Close()

	machinePrivKey, _ := crypto.GenerateECKeyPair()
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	client := NewClient(ts.URL, "test-machine-id", machinePrivKey, &orgPrivKey.PublicKey)

	_, err := client.Heartbeat(HeartbeatRequest{LicenseKey: "K", MachineID: "M"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *apiError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "Internal Server Error" {
		t.Errorf("unexpected message: %s", apiErr.Message)
	}
}

// ---------------------------------------------------------------------------
// IsConnectionError
// ---------------------------------------------------------------------------

func TestIsConnectionError_WithApiError(t *testing.T) {
	err := &apiError{StatusCode: 400, Message: "bad request"}
	if IsConnectionError(err) {
		t.Error("*apiError should not be a connection error")
	}
}

func TestIsConnectionError_WithNetworkError(t *testing.T) {
	// Point client at a closed server to force a real network error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	machinePrivKey, _ := crypto.GenerateECKeyPair()
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	client := NewClient(ts.URL, "m", machinePrivKey, &orgPrivKey.PublicKey)

	_, err := client.Heartbeat(HeartbeatRequest{LicenseKey: "K", MachineID: "M"})
	if err == nil {
		t.Fatal("expected network error")
	}
	if !IsConnectionError(err) {
		t.Errorf("network-level error should be a connection error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DetectPlatform
// ---------------------------------------------------------------------------

func TestDetectPlatform_NonEmpty(t *testing.T) {
	p := DetectPlatform()
	if p == "" {
		t.Error("DetectPlatform returned empty string")
	}
}

func TestDetectPlatform_FormatIsUppercaseWithUnderscore(t *testing.T) {
	p := DetectPlatform()
	if strings.Contains(p, "/") || strings.Contains(p, "-") {
		t.Errorf("platform should use underscore format, got: %s", p)
	}
	if p != strings.ToUpper(p) {
		t.Errorf("platform should be uppercase, got: %s", p)
	}
	if !strings.Contains(p, "_") {
		t.Errorf("platform should contain an underscore, got: %s", p)
	}
}
