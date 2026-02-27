# Phase 5 — DRM Server Communication

**Status**: Pending
**Depends on**: Phase 1 (crypto), Phase 4 (state)

---

## Goals

- Implement the HTTP client for the three DRM backend endpoints: activate, heartbeat,
  decommission-ack.
- Sign all outbound requests with the machine's EC private key.
- Verify all server response signatures with the embedded org public key.
- Verify reflected nonce in responses to prevent replay attacks.

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/drm/drm.go` | Created — DRM client, request signing, response verification |

---

## Request Signing Protocol

Every request to `/api/v1/drm/` includes these HTTP headers:

```
X-Sentinel-Machine-Id:  <machine_id>
X-Sentinel-Timestamp:   <Unix epoch seconds as integer string>
X-Sentinel-Nonce:       <UUID v4 string>
X-Sentinel-Signature:   <base64url(DER-encoded ECDSA-SHA256 signature)>
```

### Signing String Construction

The signing string is built from these 5 lines joined by `\n`:

```
{METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256_HEX(BODY)}
```

Where:
- `METHOD` = `"POST"` (all DRM endpoints are POST)
- `PATH` = URL path only, e.g., `/api/v1/drm/activate/` (must include trailing slash)
- `TIMESTAMP` = unix seconds as decimal string (e.g., `"1708869000"`)
- `NONCE` = UUID v4 string (e.g., `"f47ac10b-58cc-4372-a567-0e02b2c3d479"`)
- `SHA256_HEX(BODY)` = hex-encoded SHA-256 of the raw request body bytes

The signature is `ECDSA-SHA256(UTF-8 bytes of signing string, machine_private_key)`.

**Example signing string:**
```
POST
/api/v1/drm/activate/
1708869000
f47ac10b-58cc-4372-a567-0e02b2c3d479
a3f5c9e1d2b3f4a5e6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8
```

### Request Construction

```go
func (c *Client) buildSignedRequest(method, path string, body []byte) (*http.Request, string, error) {
    timestamp := strconv.FormatInt(time.Now().Unix(), 10)
    nonce := uuid.New().String()
    bodyHash := crypto.SHA256Hex(body)

    signingString := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", method, path, timestamp, nonce, bodyHash)

    sig, err := crypto.SignECDSA(c.machineKey, []byte(signingString))
    if err != nil {
        return nil, "", fmt.Errorf("sign request: %w", err)
    }

    url := c.serverURL + path
    req, err := http.NewRequest(method, url, bytes.NewReader(body))
    if err != nil {
        return nil, "", err
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Sentinel-Machine-Id", c.machineID)
    req.Header.Set("X-Sentinel-Timestamp", timestamp)
    req.Header.Set("X-Sentinel-Nonce", nonce)
    req.Header.Set("X-Sentinel-Signature", crypto.Base64URLEncode(sig))

    return req, nonce, nil // return nonce for response verification
}
```

---

## Response Verification

### Response Envelope

Every backend response has this JSON shape:

```json
{
  "payload": "<base64url(canonical_json)>",
  "sig": "<base64url(DER-encoded ECDSA-SHA256 signature)>"
}
```

### Verification Steps

```go
func (c *Client) verifyAndDecode(httpResp *http.Response, expectedNonce string, target any) error {
    // 1. Read response body
    body, err := io.ReadAll(httpResp.Body)

    // 2. Check HTTP status code
    if httpResp.StatusCode != http.StatusOK {
        // Parse error response: {"error": "..."}
        return parseErrorResponse(httpResp.StatusCode, body)
    }

    // 3. Unmarshal response envelope
    var envelope struct {
        Payload string `json:"payload"`
        Sig     string `json:"sig"`
    }
    json.Unmarshal(body, &envelope)

    // 4. Decode signature
    sigBytes := crypto.Base64URLDecode(envelope.Sig)

    // 5. Verify signature over the payload base64url STRING (not decoded bytes)
    err = crypto.VerifyECDSA(c.orgPubKey, []byte(envelope.Payload), sigBytes)
    if err != nil {
        return errors.New("server response signature verification failed")
    }

    // 6. Decode payload
    payloadBytes := crypto.Base64URLDecode(envelope.Payload)

    // 7. Unmarshal into target struct
    json.Unmarshal(payloadBytes, target)

    // 8. Verify reflected nonce
    // target must have a RequestNonce field
    nonce := extractRequestNonce(target)
    if nonce != expectedNonce {
        return fmt.Errorf("response nonce mismatch: expected %s, got %s", expectedNonce, nonce)
    }

    return nil
}
```

**Nonce verification is critical**: Without it, an attacker could replay a previous
valid response. The server includes the request nonce in the signed payload, so
forging a response with the correct nonce requires the org's private key.

---

## Client Struct

```go
type Client struct {
    serverURL  string
    machineID  string
    machineKey *ecdsa.PrivateKey
    orgPubKey  *ecdsa.PublicKey
    httpClient *http.Client
}

func NewClient(serverURL, machineID string, machineKey *ecdsa.PrivateKey, orgPubKey *ecdsa.PublicKey) *Client {
    return &Client{
        serverURL:  strings.TrimRight(serverURL, "/"),
        machineID:  machineID,
        machineKey: machineKey,
        orgPubKey:  orgPubKey,
        httpClient: &http.Client{Timeout: 30 * time.Second},
    }
}
```

---

## Endpoints

### `Activate`

```go
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

func (c *Client) Activate(req ActivateRequest) (*ActivateResponse, error)
```

**Path**: `/api/v1/drm/activate/`

**Error handling**: Backend returns `400` with `{"error": "..."}` for validation
errors (license not found, expired, max machines reached, etc.). Parse the error
message and return it as a Go error.

### `Heartbeat`

```go
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

func (c *Client) Heartbeat(req HeartbeatRequest) (*HeartbeatResponse, error)
```

**Path**: `/api/v1/drm/heartbeat/`

### `DecommissionAck`

```go
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

func (c *Client) DecommissionAck(req DecommissionAckRequest) (*DecommissionAckResponse, error)
```

**Path**: `/api/v1/drm/decommission-ack/`

---

## Platform Detection

The `platform` field sent during activation must match the backend's `Platform` choices.

```go
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
        return runtime.GOOS + "_" + runtime.GOARCH // best effort
    }
}
```

---

## Error Response Parsing

Backend error format: `{"error": "Human-readable error message"}`.

```go
type apiError struct {
    StatusCode int
    Message    string
}

func (e *apiError) Error() string {
    return fmt.Sprintf("DRM server error (%d): %s", e.StatusCode, e.Message)
}

func parseErrorResponse(statusCode int, body []byte) error {
    var resp struct {
        Error string `json:"error"`
    }
    if err := json.Unmarshal(body, &resp); err != nil {
        return &apiError{StatusCode: statusCode, Message: string(body)}
    }
    return &apiError{StatusCode: statusCode, Message: resp.Error}
}
```

---

## Connection Error vs Server Error

The caller (orchestrator, Phase 7) needs to distinguish between:

1. **Connection errors** (server unreachable, DNS failure, timeout) — consume grace period
2. **Server errors** (400/401/503) — act on the error (don't consume grace)

```go
func IsConnectionError(err error) bool {
    var apiErr *apiError
    if errors.As(err, &apiErr) {
        return false // got an HTTP response, not a connection error
    }
    return true // network-level failure
}
```

---

## Done Criteria

- [ ] Request signing string matches backend's expected format exactly
- [ ] Signing string includes correct HTTP method, path, timestamp, nonce, and body hash
- [ ] Request headers are set correctly (`X-Sentinel-Machine-Id`, `X-Sentinel-Timestamp`,
  `X-Sentinel-Nonce`, `X-Sentinel-Signature`)
- [ ] Response signature is verified against org public key
- [ ] Response nonce mismatch causes error
- [ ] Backend error responses are parsed into descriptive Go errors
- [ ] Connection errors are distinguishable from server errors
- [ ] `DetectPlatform()` returns correct values for all 5 supported platforms
- [ ] All three endpoints (`Activate`, `Heartbeat`, `DecommissionAck`) correctly
  marshal requests and unmarshal responses
- [ ] Cross-language test: Go client can communicate with the Python backend
  (sign request, verify response) — requires running backend
