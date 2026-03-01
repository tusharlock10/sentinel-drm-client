package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func dialSocket(socketPath string) (net.Conn, error) {
	return net.Dial("unix", socketPath)
}

// testLicenseInfo returns a sample LicenseInfo for use in tests.
func testLicenseInfo() *LicenseInfo {
	return &LicenseInfo{
		LicenseKey:  "SENTINEL-TEST-0001",
		LicenseType: "STANDARD",
		ExpiryDate:  "2027-01-01",
		Features:    map[string]any{"max_users": float64(100)},
		OrgID:       "org-uuid-123",
		SoftwareID:  "sw-uuid-456",
	}
}

// newTestServer creates a Server with no listener for direct handleRequest unit tests.
func newTestServer(info *LicenseInfo) *Server {
	return &Server{licenseInfo: info}
}

// ---------------------------------------------------------------------------
// handleRequest unit tests
// ---------------------------------------------------------------------------

func TestHandleRequest_GetLicense(t *testing.T) {
	srv := newTestServer(testLicenseInfo())
	resp := srv.handleRequest(Request{Method: "get_license"})

	if resp.Status != "ok" {
		t.Fatalf("expected status ok, got %q", resp.Status)
	}
	if resp.License == nil {
		t.Fatal("expected non-nil license in response")
	}
	if resp.License.LicenseKey != "SENTINEL-TEST-0001" {
		t.Errorf("license_key: expected SENTINEL-TEST-0001, got %s", resp.License.LicenseKey)
	}
	if resp.License.OrgID != "org-uuid-123" {
		t.Errorf("org_id: expected org-uuid-123, got %s", resp.License.OrgID)
	}
}

func TestHandleRequest_GetFeatures(t *testing.T) {
	srv := newTestServer(testLicenseInfo())
	resp := srv.handleRequest(Request{Method: "get_features"})

	if resp.Status != "ok" {
		t.Fatalf("expected status ok, got %q", resp.Status)
	}
	if resp.Features == nil {
		t.Fatal("expected non-nil features map")
	}
	maxUsers, ok := resp.Features["max_users"]
	if !ok {
		t.Fatal("expected max_users key in features")
	}
	if maxUsers != float64(100) {
		t.Errorf("max_users: expected 100, got %v", maxUsers)
	}
}

func TestHandleRequest_Health(t *testing.T) {
	srv := newTestServer(testLicenseInfo())
	resp := srv.handleRequest(Request{Method: "health"})

	if resp.Status != "ok" {
		t.Fatalf("expected status ok, got %q", resp.Status)
	}
	if resp.License != nil || resp.Features != nil || resp.Error != "" {
		t.Error("health response should contain only status")
	}
}

func TestHandleRequest_UnknownMethod(t *testing.T) {
	srv := newTestServer(testLicenseInfo())
	resp := srv.handleRequest(Request{Method: "nonexistent_method"})

	if resp.Status != "error" {
		t.Fatalf("expected status error, got %q", resp.Status)
	}
	if !strings.Contains(resp.Error, "unknown method") {
		t.Errorf("expected 'unknown method' in error, got: %s", resp.Error)
	}
}

func TestHandleRequest_EmptyMethod(t *testing.T) {
	srv := newTestServer(testLicenseInfo())
	resp := srv.handleRequest(Request{Method: ""})

	if resp.Status != "error" {
		t.Fatalf("expected error for empty method, got %q", resp.Status)
	}
}

// ---------------------------------------------------------------------------
// SetDegradeStage
// ---------------------------------------------------------------------------

func TestSetDegradeStage(t *testing.T) {
	srv := newTestServer(testLicenseInfo())

	if DegradeStage(srv.degradeStage.Load()) != StageNormal {
		t.Error("initial stage should be StageNormal")
	}

	srv.SetDegradeStage(StageErrors)
	if DegradeStage(srv.degradeStage.Load()) != StageErrors {
		t.Error("stage should be StageErrors after SetDegradeStage(StageErrors)")
	}

	srv.SetDegradeStage(StageCrash)
	if DegradeStage(srv.degradeStage.Load()) != StageCrash {
		t.Error("stage should be StageCrash after SetDegradeStage(StageCrash)")
	}
}

// ---------------------------------------------------------------------------
// Full server integration test
// (dialSocket is defined in ipc_unix_test.go / ipc_windows_test.go)
// ---------------------------------------------------------------------------

func TestServerServe(t *testing.T) {
	machineID := "test-integration-machine"
	socketPath := SocketPath(machineID)
	info := testLicenseInfo()

	srv, err := NewServer(socketPath, info)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.Serve(ctx)
	}()

	// Give the server a moment to start accepting connections.
	time.Sleep(50 * time.Millisecond)

	conn, err := dialSocket(socketPath)
	if err != nil {
		t.Fatalf("dial IPC socket: %v", err)
	}
	defer conn.Close()

	scanner := bufio.NewScanner(conn)

	// sendEncrypted encrypts a method request and writes it to conn.
	sendEncrypted := func(method string) error {
		data, _ := json.Marshal(Request{Method: method})
		line, err := encryptMessage(ipcKey, data)
		if err != nil {
			return err
		}
		_, err = conn.Write([]byte(line + "\n"))
		return err
	}

	// recvDecrypted reads one encrypted line from scanner and decrypts it.
	recvDecrypted := func() (Response, error) {
		if !scanner.Scan() {
			return Response{}, scanner.Err()
		}
		plaintext, err := decryptMessage(ipcKey, scanner.Text())
		if err != nil {
			return Response{}, err
		}
		var resp Response
		return resp, json.Unmarshal(plaintext, &resp)
	}

	tests := []struct {
		method       string
		wantStatus   string
		wantLicense  bool
		wantFeatures bool
	}{
		{"health", "ok", false, false},
		{"get_license", "ok", true, false},
		{"get_features", "ok", false, true},
		{"bad_method", "error", false, false},
	}

	for _, tc := range tests {
		if err := sendEncrypted(tc.method); err != nil {
			t.Fatalf("send request %q: %v", tc.method, err)
		}
		resp, err := recvDecrypted()
		if err != nil {
			t.Fatalf("recv response for %q: %v", tc.method, err)
		}
		if resp.Status != tc.wantStatus {
			t.Errorf("%q: expected status %q, got %q", tc.method, tc.wantStatus, resp.Status)
		}
		if tc.wantLicense && resp.License == nil {
			t.Errorf("%q: expected non-nil license", tc.method)
		}
		if tc.wantFeatures && resp.Features == nil {
			t.Errorf("%q: expected non-nil features", tc.method)
		}
	}

	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("Serve returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not return after context cancellation")
	}
}
