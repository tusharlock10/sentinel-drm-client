# Phase 2 — License File Parsing and Verification

**Status**: Pending
**Depends on**: Phase 1

---

## Goals

- Parse `.lic` files from disk.
- Verify the ECDSA signature against the embedded org public key.
- Extract and validate the license payload fields.

---

## Files Created / Modified

| File | Action |
|---|---|
| `internal/license/license.go` | Created — envelope parsing, signature verification, payload validation |

---

## License File Format

The `.lic` file is a JSON document with this structure:

```json
{
  "alg": "ES256",
  "payload": "<base64url(canonical_json)>",
  "sig": "<base64url(DER-encoded ECDSA-SHA256 signature)>"
}
```

**Critical**: The signature is computed over the **raw base64url string** (the value
of the `payload` field), NOT the decoded JSON bytes. This matches the backend's
signing implementation in `license/crypto.py:sign_license_payload()`.

---

## Structs

### `LicenseEnvelope`

The raw JSON structure of the `.lic` file.

```go
type LicenseEnvelope struct {
    Alg     string `json:"alg"`
    Payload string `json:"payload"`
    Sig     string `json:"sig"`
}
```

### `LicenseType`

```go
type LicenseType string

const (
    LicenseTypeStandard      LicenseType = "STANDARD"
    LicenseTypeHardwareBound LicenseType = "HARDWARE_BOUND"
)
```

### `LicensePayload`

The decoded payload. Fields match the backend's `build_license_payload()` in
`license/signing.py`.

```go
type LicensePayload struct {
    V           int            `json:"v"`
    LicenseKey  string         `json:"license_key"`
    OrgID       string         `json:"org_id"`
    SoftwareID  string         `json:"software_id"`
    LicenseType LicenseType    `json:"license_type"`
    IssueDate   string         `json:"issue_date"`    // "YYYY-MM-DD"
    ExpiryDate  string         `json:"expiry_date"`   // "YYYY-MM-DD"
    MaxMachines int            `json:"max_machines"`
    Features    map[string]any `json:"features"`
    IssuedAt    string         `json:"issued_at"`     // ISO 8601

    // STANDARD only (omitted from JSON for HARDWARE_BOUND)
    ServerURL                *string `json:"server_url,omitempty"`                 // DRM backend base URL
    HeartbeatIntervalMinutes *int    `json:"heartbeat_interval_minutes,omitempty"`
    HeartbeatGracePeriodDays *int    `json:"heartbeat_grace_period_days,omitempty"`

    // HARDWARE_BOUND only (omitted from JSON for STANDARD)
    HardwareFingerprint *string `json:"hardware_fingerprint,omitempty"`
}
```

---

## Functions

### `LoadAndVerify(path string, orgPubKey *ecdsa.PublicKey) (*LicensePayload, error)`

Main entry point. Loads a `.lic` file and returns the verified, validated payload.

**Steps:**

1. **Read file**: `os.ReadFile(path)`. Return error if file doesn't exist or can't be read.

2. **Unmarshal envelope**: JSON decode into `LicenseEnvelope`. Return error if JSON
   is malformed.

3. **Check algorithm**: Verify `envelope.Alg == "ES256"`. Return error if not.
   This is a safety check — the backend always signs with ES256.

4. **Decode signature**: `crypto.Base64URLDecode(envelope.Sig)`. Return error if
   decoding fails.

5. **Verify signature**: `crypto.VerifyECDSA(orgPubKey, []byte(envelope.Payload), sigBytes)`.
   The signed data is the raw base64url string bytes of the payload field — NOT
   the decoded content. Return error if signature is invalid.

6. **Decode payload**: `crypto.Base64URLDecode(envelope.Payload)`. This yields the
   canonical JSON bytes.

7. **Unmarshal payload**: JSON decode into `LicensePayload`. Return error if JSON
   is malformed.

8. **Validate payload**: Call `validatePayload()`.

9. **Return**: `&payload, nil`

### `validatePayload(p *LicensePayload) error`

Validates all required fields and type-specific constraints.

**Checks:**

1. `p.V` must be `1` (only version supported). Return error if not.

2. `p.LicenseKey` must be non-empty.

3. `p.OrgID` must be non-empty.

4. `p.SoftwareID` must be non-empty.

5. `p.LicenseType` must be `"STANDARD"` or `"HARDWARE_BOUND"`.

6. `p.IssueDate` must parse as `"2006-01-02"` (Go time format).

7. `p.ExpiryDate` must parse as `"2006-01-02"` (Go time format).

8. **Expiry check**: Parsed `ExpiryDate` must be >= today (UTC).
   Return error: `"license has expired (expiry: YYYY-MM-DD)"`.

9. `p.MaxMachines` must be >= 1.

10. **STANDARD-specific**:
    - `HeartbeatIntervalMinutes` must be non-nil and > 0.
    - `HeartbeatGracePeriodDays` must be non-nil and > 0.
    - `HardwareFingerprint` must be nil or empty.

11. **HARDWARE_BOUND-specific**:
    - `HardwareFingerprint` must be non-nil and non-empty.
    - `HeartbeatIntervalMinutes` must be nil.
    - `HeartbeatGracePeriodDays` must be nil.

### `IsExpired(p *LicensePayload) bool`

Utility to check if the license has expired. Used by the orchestrator during runtime
(heartbeat loop may run past midnight).

```go
func IsExpired(p *LicensePayload) bool {
    expiry, err := time.Parse("2006-01-02", p.ExpiryDate)
    if err != nil {
        return true // unparseable = treat as expired
    }
    return time.Now().UTC().Truncate(24 * time.Hour).After(expiry)
}
```

---

## Error Messages

All errors should be descriptive and include context:

```
"license file not found: /path/to/file.lic"
"invalid license file: malformed JSON"
"unsupported license algorithm: RS256 (expected ES256)"
"license signature verification failed"
"invalid license payload: malformed JSON"
"license version 2 is not supported (expected 1)"
"license has expired (expiry: 2025-01-01)"
"STANDARD license missing server_url"
"STANDARD license missing heartbeat_interval_minutes"
"HARDWARE_BOUND license missing hardware_fingerprint"
```

---

## Done Criteria

- [ ] `LoadAndVerify` correctly parses a valid `.lic` file and returns the payload
- [ ] Signature verification fails with a wrong public key (different org key)
- [ ] Signature verification fails with a tampered payload
- [ ] Expired licenses are rejected with a clear error message
- [ ] Unknown `license_type` values are rejected
- [ ] STANDARD licenses missing `server_url` are rejected
- [ ] STANDARD licenses missing heartbeat fields are rejected
- [ ] HARDWARE_BOUND licenses missing fingerprint are rejected
- [ ] `IsExpired` returns correct results for past, today, and future dates
- [ ] Payloads generated by the Python backend can be verified by this Go implementation
  (cross-language signature verification)
