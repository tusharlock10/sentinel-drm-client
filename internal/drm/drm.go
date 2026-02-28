package drm

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tusharlock10/sentinel-drm-client/internal/crypto"
)

// maxResponseBodySize caps the response body read to prevent memory exhaustion.
const maxResponseBodySize = 1 << 20 // 1 MB

// Client communicates with the Sentinel DRM backend on behalf of a single machine.
type Client struct {
	serverURL  string
	machineID  string
	machineKey *ecdsa.PrivateKey
	orgPubKey  *ecdsa.PublicKey
	httpClient *http.Client
}

// NewClient constructs a DRM client. serverURL is stripped of a trailing slash.
func NewClient(serverURL, machineID string, machineKey *ecdsa.PrivateKey, orgPubKey *ecdsa.PublicKey) *Client {
	return &Client{
		serverURL:  strings.TrimRight(serverURL, "/"),
		machineID:  machineID,
		machineKey: machineKey,
		orgPubKey:  orgPubKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// DetectPlatform returns the platform string expected by the DRM backend.
func DetectPlatform() string {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
		return "LINUX_AMD64"
	case "linux/arm64":
		return "LINUX_ARM64"
	case "windows/amd64":
		return "WINDOWS_AMD64"
	case "windows/arm64":
		return "WINDOWS_ARM64"
	case "darwin/arm64":
		return "DARWIN_ARM64"
	default:
		return strings.ToUpper(runtime.GOOS) + "_" + strings.ToUpper(runtime.GOARCH)
	}
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

// apiError is a structured error returned by the DRM backend (HTTP 4xx/5xx).
type apiError struct {
	StatusCode int
	Message    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("DRM server error (%d): %s", e.StatusCode, e.Message)
}

// IsConnectionError reports whether err is a network-level failure rather than
// an HTTP response error. The orchestrator uses this to decide whether a failed
// heartbeat should consume the grace period (connection error) or trigger an
// immediate action (server error).
func IsConnectionError(err error) bool {
	var apiErr *apiError
	return !errors.As(err, &apiErr)
}

// parseErrorResponse parses the backend error body into an *apiError.
// Backend error format: {"error": "Human-readable message"}
func parseErrorResponse(statusCode int, body []byte) error {
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Error == "" {
		return &apiError{StatusCode: statusCode, Message: string(body)}
	}
	return &apiError{StatusCode: statusCode, Message: resp.Error}
}

// ---------------------------------------------------------------------------
// Request signing
// ---------------------------------------------------------------------------

// buildSignedRequest constructs a signed POST request for a DRM endpoint.
// Returns the request and the nonce (needed for response nonce verification).
//
// Signing string format (must match backend signing.py exactly):
//
//	POST\n{path}\n{timestamp}\n{nonce}\n{sha256_hex(body)}
func (c *Client) buildSignedRequest(path string, body []byte) (*http.Request, string, error) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := uuid.New().String()
	bodyHash := crypto.SHA256Hex(body)

	signingString := fmt.Sprintf("POST\n%s\n%s\n%s\n%s", path, timestamp, nonce, bodyHash)

	sig, err := crypto.SignECDSA(c.machineKey, []byte(signingString))
	if err != nil {
		return nil, "", fmt.Errorf("sign request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.serverURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Machine-Id", c.machineID)
	req.Header.Set("X-Sentinel-Timestamp", timestamp)
	req.Header.Set("X-Sentinel-Nonce", nonce)
	req.Header.Set("X-Sentinel-Signature", crypto.Base64URLEncode(sig))

	return req, nonce, nil
}

// ---------------------------------------------------------------------------
// Response verification
// ---------------------------------------------------------------------------

// verifyAndDecode reads, signature-verifies, nonce-checks, and decodes a signed
// backend response into target. The response envelope format is:
//
//	{"payload": "<base64url(canonical_json)>", "sig": "<base64url(der_sig)>"}
//
// The signature is over the raw base64url payload STRING bytes (not the decoded JSON).
func (c *Client) verifyAndDecode(httpResp *http.Response, expectedNonce string, target any) error {
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return parseErrorResponse(httpResp.StatusCode, body)
	}

	var envelope struct {
		Payload string `json:"payload"`
		Sig     string `json:"sig"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("parse response envelope: %w", err)
	}

	sigBytes, err := crypto.Base64URLDecode(envelope.Sig)
	if err != nil {
		return fmt.Errorf("decode response signature: %w", err)
	}

	// Signature is over the raw base64url payload string, not the decoded JSON.
	if err := crypto.VerifyECDSA(c.orgPubKey, []byte(envelope.Payload), sigBytes); err != nil {
		return errors.New("server response signature verification failed")
	}

	payloadBytes, err := crypto.Base64URLDecode(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decode response payload: %w", err)
	}

	// Verify the reflected nonce before decoding into the target struct.
	var nonceHolder struct {
		RequestNonce string `json:"request_nonce"`
	}
	if err := json.Unmarshal(payloadBytes, &nonceHolder); err != nil {
		return fmt.Errorf("parse response payload for nonce: %w", err)
	}
	if nonceHolder.RequestNonce != expectedNonce {
		return fmt.Errorf("response nonce mismatch: expected %s, got %s", expectedNonce, nonceHolder.RequestNonce)
	}

	if err := json.Unmarshal(payloadBytes, target); err != nil {
		return fmt.Errorf("decode response into target: %w", err)
	}

	return nil
}

// do marshals reqBody, sends a signed POST to path, verifies and decodes the response.
func (c *Client) do(path string, reqBody any, target any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}

	req, nonce, err := c.buildSignedRequest(path, body)
	if err != nil {
		return err
	}

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DRM request to %s failed: %w", path, err)
	}

	return c.verifyAndDecode(httpResp, nonce, target)
}

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------

type ActivateRequest struct {
	LicenseKey          string `json:"license_key"`
	MachineID           string `json:"machine_id"`
	MachinePublicKeyPEM string `json:"machine_public_key_pem"`
	Platform            string `json:"platform"`
	SoftwareVersion     string `json:"software_version"`
}

type ActivateResponse struct {
	Status                   string         `json:"status"`
	MachineID                string         `json:"machine_id"`
	LicenseKey               string         `json:"license_key"`
	ExpiryDate               string         `json:"expiry_date"`
	HeartbeatIntervalMinutes int            `json:"heartbeat_interval_minutes"`
	HeartbeatGracePeriodDays int            `json:"heartbeat_grace_period_days"`
	Features                 map[string]any `json:"features"`
	RequestNonce             string         `json:"request_nonce"`
	RespondedAt              string         `json:"responded_at"`
}

// Activate registers this machine with the DRM backend. Called once at first startup
// for STANDARD licenses. Re-activation with the same machine_id is idempotent.
func (c *Client) Activate(req ActivateRequest) (*ActivateResponse, error) {
	var resp ActivateResponse
	if err := c.do("/api/v1/drm/activate/", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

type HeartbeatRequest struct {
	LicenseKey      string `json:"license_key"`
	MachineID       string `json:"machine_id"`
	SoftwareVersion string `json:"software_version"`
}

type HeartbeatResponse struct {
	Status              string `json:"status"`
	MachineID           string `json:"machine_id"`
	LicenseKey          string `json:"license_key"`
	ExpiryDate          string `json:"expiry_date"`
	DecommissionPending bool   `json:"decommission_pending"`
	RequestNonce        string `json:"request_nonce"`
	RespondedAt         string `json:"responded_at"`
}

// Heartbeat sends a periodic check-in to the DRM backend.
func (c *Client) Heartbeat(req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.do("/api/v1/drm/heartbeat/", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// DecommissionAck
// ---------------------------------------------------------------------------

type DecommissionAckRequest struct {
	LicenseKey string `json:"license_key"`
	MachineID  string `json:"machine_id"`
}

type DecommissionAckResponse struct {
	Status       string `json:"status"`
	MachineID    string `json:"machine_id"`
	LicenseKey   string `json:"license_key"`
	RequestNonce string `json:"request_nonce"`
	RespondedAt  string `json:"responded_at"`
}

// DecommissionAck acknowledges a pending decommission from the DRM backend.
// Called after receiving DecommissionPending=true in a heartbeat response.
func (c *Client) DecommissionAck(req DecommissionAckRequest) (*DecommissionAckResponse, error) {
	var resp DecommissionAckResponse
	if err := c.do("/api/v1/drm/decommission-ack/", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
