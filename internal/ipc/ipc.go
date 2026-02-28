package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
)

// DegradeStage controls IPC response degradation for anti-tamper (Phase 8).
type DegradeStage int

const (
	StageNormal   DegradeStage = iota // normal operation
	StageWarnings                     // emit cryptic warnings; no IPC effect yet
	StageErrors                       // inject fake errors into responses
	StageSlowdown                     // resource pressure + error injection
	StageCrash                        // eventual self-termination
)

// Request is a single IPC request line sent by the managed software.
type Request struct {
	Method string `json:"method"`
}

// Response is the IPC response written back to the managed software.
type Response struct {
	Status   string         `json:"status"`
	Error    string         `json:"error,omitempty"`
	Features map[string]any `json:"features,omitempty"`
	License  *LicenseInfo   `json:"license,omitempty"`
}

// LicenseInfo is the license metadata exposed to the managed software over IPC.
type LicenseInfo struct {
	LicenseKey  string         `json:"license_key"`
	LicenseType string         `json:"license_type"`
	ExpiryDate  string         `json:"expiry_date"`
	Features    map[string]any `json:"features"`
	OrgID       string         `json:"org_id"`
	SoftwareID  string         `json:"software_id"`
}

// Server serves license metadata to the managed software over a Unix domain socket
// (Linux/macOS) or a named pipe (Windows).
type Server struct {
	socketPath   string
	listener     net.Listener
	licenseInfo  *LicenseInfo
	degradeStage atomic.Int32 // DegradeStage cast to int32
	mu           sync.Mutex
}

// SocketPath returns the platform-appropriate IPC socket path for the given machine ID.
func SocketPath(machineID string) string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\sentinel-` + machineID
	}
	return "/tmp/sentinel-" + machineID + ".sock"
}

// NewServer creates the IPC listener and returns a Server ready to call Serve on.
func NewServer(socketPath string, info *LicenseInfo) (*Server, error) {
	ln, err := newListener(socketPath)
	if err != nil {
		return nil, fmt.Errorf("create IPC listener: %w", err)
	}
	return &Server{
		socketPath:  socketPath,
		listener:    ln,
		licenseInfo: info,
	}, nil
}

// Serve accepts connections until ctx is cancelled. Returns nil on clean shutdown.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("IPC accept: %w", err)
			}
		}
		go s.handleConnection(conn)
	}
}

// Close closes the listener and removes the socket file (Unix) or pipe handle (Windows).
func (s *Server) Close() error {
	err := s.listener.Close()
	cleanupListener(s.socketPath)
	return err
}

// SetDegradeStage advances the anti-tamper degradation stage.
// Called by the anti-tamper monitor (Phase 8) upon detecting tampering.
func (s *Server) SetDegradeStage(stage DegradeStage) {
	s.degradeStage.Store(int32(stage))
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	encoder := json.NewEncoder(conn)

	for scanner.Scan() {
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			encoder.Encode(Response{Status: "error", Error: "malformed request"}) //nolint:errcheck
			continue
		}
		encoder.Encode(s.handleRequest(req)) //nolint:errcheck
	}
}

func (s *Server) handleRequest(req Request) Response {
	stage := DegradeStage(s.degradeStage.Load())

	if stage >= StageErrors && shouldInjectError() {
		return Response{Status: "error", Error: randomSystemError()}
	}

	switch req.Method {
	case "get_license":
		if stage >= StageErrors {
			return degradedLicenseResponse(s.licenseInfo)
		}
		return Response{Status: "ok", License: s.licenseInfo}

	case "get_features":
		if stage >= StageErrors {
			return Response{Status: "ok", Features: degradedFeatures(s.licenseInfo.Features)}
		}
		return Response{Status: "ok", Features: s.licenseInfo.Features}

	case "health":
		return Response{Status: "ok"}

	default:
		return Response{Status: "error", Error: fmt.Sprintf("unknown method: %s", req.Method)}
	}
}

// ---------------------------------------------------------------------------
// Degradation stubs — fully implemented in Phase 8.
// ---------------------------------------------------------------------------

var systemErrors = []string{
	"connection reset by peer",
	"broken pipe",
	"resource temporarily unavailable",
	"no such file or directory",
}

func shouldInjectError() bool {
	return rand.Intn(3) == 0
}

func randomSystemError() string {
	return systemErrors[rand.Intn(len(systemErrors))]
}

func degradedLicenseResponse(_ *LicenseInfo) Response {
	return Response{Status: "error", Error: "license validation failed"}
}

func degradedFeatures(_ map[string]any) map[string]any {
	return map[string]any{}
}
