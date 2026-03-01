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
	orgPubKey  *ecdsa.PublicKey
	httpClient *http.Client
}

// NewClient constructs a DRM client. serverURL is stripped of a trailing slash.
func NewClient(serverURL string, orgPubKey *ecdsa.PublicKey) *Client {
	return &Client{
		serverURL:  strings.TrimRight(serverURL, "/"),
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
// an HTTP response error. The orchestrator uses this to decide whether to retry
// or shut down immediately.
func IsConnectionError(err error) bool {
	var apiErr *apiError
	return !errors.As(err, &apiErr)
}

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
// Response verification
// ---------------------------------------------------------------------------

// verifyAndDecode reads, signature-verifies, nonce-checks, and decodes a signed
// backend response into target. expectedNonce is the nonce sent in X-Sentinel-Nonce.
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

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

type RegisterRequest struct {
	LicenseKey      string `json:"license_key"`
	Platform        string `json:"platform"`
	SoftwareVersion string `json:"software_version"`
}

type RegisterResponse struct {
	Status       string `json:"status"`
	Token        string `json:"token"`
	RequestNonce string `json:"request_nonce"`
}

// Register creates a new ephemeral machine registration and returns a session token.
// Called once at startup for STANDARD licenses.
func (c *Client) Register(req RegisterRequest) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal register request: %w", err)
	}

	nonce := uuid.New().String()

	httpReq, err := http.NewRequest(http.MethodPost, c.serverURL+"/api/v1/drm/register/", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build register request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Sentinel-Nonce", nonce)

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DRM register request failed: %w", err)
	}

	var resp RegisterResponse
	if err := c.verifyAndDecode(httpResp, nonce, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

type HeartbeatResponse struct {
	Status       string `json:"status"`
	RequestNonce string `json:"request_nonce"`
}

// Heartbeat sends a periodic check-in to the DRM backend.
// token is the session token received from Register and held in memory.
func (c *Client) Heartbeat(token string) (*HeartbeatResponse, error) {
	nonce := uuid.New().String()

	httpReq, err := http.NewRequest(http.MethodGet, c.serverURL+"/api/v1/drm/heartbeat/", nil)
	if err != nil {
		return nil, fmt.Errorf("build heartbeat request: %w", err)
	}
	httpReq.Header.Set("X-Sentinel-Token", token)
	httpReq.Header.Set("X-Sentinel-Nonce", nonce)

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DRM heartbeat request failed: %w", err)
	}

	var resp HeartbeatResponse
	if err := c.verifyAndDecode(httpResp, nonce, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
