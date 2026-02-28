package drm

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
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
// It receives the nonce from the X-Sentinel-Nonce header so it can be reflected.
type responseBuilder func(nonce string, orgPrivKey *ecdsa.PrivateKey) []byte

// newMockServer starts a test HTTP server for a single DRM endpoint.
// Returns the client and the org private key (for signing mock responses).
func newMockServer(t *testing.T, expectedPath string, buildResp responseBuilder) (*Client, *ecdsa.PrivateKey, *httptest.Server) {
	t.Helper()

	orgPrivKey, err := crypto.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate org keypair: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expectedPath {
			t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		nonce := r.Header.Get("X-Sentinel-Nonce")
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildResp(nonce, orgPrivKey))
	}))

	client := NewClient(ts.URL, &orgPrivKey.PublicKey)
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

func registerPayload(nonce string) map[string]any {
	return map[string]any{
		"token":                      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"license_key":                "SENTINEL-TEST-0001",
		"expiry_date":                "2027-01-01",
		"heartbeat_interval_minutes": 15,
		"features":                   map[string]any{"max_users": float64(500)},
		"request_nonce":              nonce,
		"responded_at":               time.Now().UTC().Format(time.RFC3339),
	}
}

func heartbeatPayload(nonce string) map[string]any {
	return map[string]any{
		"status":        "ACTIVE",
		"license_key":   "SENTINEL-TEST-0001",
		"expiry_date":   "2027-01-01",
		"request_nonce": nonce,
		"responded_at":  time.Now().UTC().Format(time.RFC3339),
	}
}

// ---------------------------------------------------------------------------
// Endpoint success tests
// ---------------------------------------------------------------------------

func TestRegister_Success(t *testing.T) {
	client, orgPrivKey, ts := newMockServer(t, "/api/v1/drm/register/", func(nonce string, orgPrivKey *ecdsa.PrivateKey) []byte {
		return signMockResponse(t, registerPayload(nonce), orgPrivKey)
	})
	defer ts.Close()
	_ = orgPrivKey

	resp, err := client.Register(RegisterRequest{
		LicenseKey:      "SENTINEL-TEST-0001",
		Platform:        DetectPlatform(),
		SoftwareVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
	if resp.HeartbeatIntervalMinutes != 15 {
		t.Errorf("expected heartbeat_interval_minutes 15, got %d", resp.HeartbeatIntervalMinutes)
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

	resp, err := client.Heartbeat("test-token")
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if resp.Status != "ACTIVE" {
		t.Errorf("expected ACTIVE, got %s", resp.Status)
	}
}

func TestHeartbeat_TokenSentInHeader(t *testing.T) {
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	const sentToken = "my-session-token-abc123"
	var receivedToken string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Sentinel-Token")
		nonce := r.Header.Get("X-Sentinel-Nonce")
		w.Header().Set("Content-Type", "application/json")
		w.Write(signMockResponse(t, heartbeatPayload(nonce), orgPrivKey))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, &orgPrivKey.PublicKey)
	_, err := client.Heartbeat(sentToken)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if receivedToken != sentToken {
		t.Errorf("expected token %q in header, got %q", sentToken, receivedToken)
	}
}

func TestHeartbeat_UsesGET(t *testing.T) {
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	var receivedMethod string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		nonce := r.Header.Get("X-Sentinel-Nonce")
		w.Header().Set("Content-Type", "application/json")
		w.Write(signMockResponse(t, heartbeatPayload(nonce), orgPrivKey))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, &orgPrivKey.PublicKey)
	_, _ = client.Heartbeat("tok")
	if receivedMethod != http.MethodGet {
		t.Errorf("expected GET heartbeat, got %s", receivedMethod)
	}
}

// ---------------------------------------------------------------------------
// Response verification error cases
// ---------------------------------------------------------------------------

func TestResponse_TamperedSignature(t *testing.T) {
	orgPrivKey, _ := crypto.GenerateECKeyPair()
	wrongPrivKey, _ := crypto.GenerateECKeyPair()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get("X-Sentinel-Nonce")
		// Sign with the wrong key — the client holds orgPrivKey's public key, so this fails.
		w.Header().Set("Content-Type", "application/json")
		w.Write(signMockResponse(t, heartbeatPayload(nonce), wrongPrivKey))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, &orgPrivKey.PublicKey)
	_, err := client.Heartbeat("tok")
	if err == nil {
		t.Fatal("expected signature verification failure, got nil error")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestResponse_NonceMismatch(t *testing.T) {
	orgPrivKey, _ := crypto.GenerateECKeyPair()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a correctly-signed response but with a stale/wrong nonce.
		stalePayload := heartbeatPayload("00000000-0000-0000-0000-000000000000")
		w.Header().Set("Content-Type", "application/json")
		w.Write(signMockResponse(t, stalePayload, orgPrivKey))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, &orgPrivKey.PublicKey)
	_, err := client.Heartbeat("tok")
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
		w.Write([]byte(`{"error": "License not found."}`))
	}))
	defer ts.Close()

	orgPrivKey, _ := crypto.GenerateECKeyPair()
	client := NewClient(ts.URL, &orgPrivKey.PublicKey)

	_, err := client.Register(RegisterRequest{LicenseKey: "INVALID"})
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
	if !strings.Contains(apiErr.Message, "License not found") {
		t.Errorf("unexpected error message: %s", apiErr.Message)
	}
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

	orgPrivKey, _ := crypto.GenerateECKeyPair()
	client := NewClient(ts.URL, &orgPrivKey.PublicKey)

	_, err := client.Heartbeat("tok")
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

	orgPrivKey, _ := crypto.GenerateECKeyPair()
	client := NewClient(ts.URL, &orgPrivKey.PublicKey)

	_, err := client.Heartbeat("tok")
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
