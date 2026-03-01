package sentinel

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/tusharlock10/sentinel-drm-client/internal/antitamper"
	"github.com/tusharlock10/sentinel-drm-client/internal/config"
	"github.com/tusharlock10/sentinel-drm-client/internal/drm"
	"github.com/tusharlock10/sentinel-drm-client/internal/hardware"
	"github.com/tusharlock10/sentinel-drm-client/internal/ipc"
	"github.com/tusharlock10/sentinel-drm-client/internal/license"
	"github.com/tusharlock10/sentinel-drm-client/internal/process"
)

// Sentinel is the main orchestrator. It wires all components together and manages
// the full lifecycle of the license-enforced software process.
type Sentinel struct {
	config    *config.Config
	orgPubKey *ecdsa.PublicKey
	license   *license.LicensePayload
	process   *process.Manager
	ipcServer *ipc.Server
}

// New creates a new Sentinel orchestrator.
func New(cfg *config.Config, orgPubKey *ecdsa.PublicKey) *Sentinel {
	return &Sentinel{
		config:    cfg,
		orgPubKey: orgPubKey,
	}
}

// SetupSignalHandler installs SIGINT/SIGTERM handlers and returns a context that
// is cancelled when a signal is received. Call before Run.
func SetupSignalHandler() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()
	return ctx, cancel
}

// Run loads the license and delegates to the appropriate flow based on license type.
func (s *Sentinel) Run(ctx context.Context) error {
	lic, err := license.LoadAndVerify(s.config.LicensePath, s.orgPubKey)
	if err != nil {
		return fmt.Errorf("license verification failed: %w", err)
	}
	s.license = lic

	switch lic.LicenseType {
	case license.LicenseTypeStandard:
		return s.runStandard(ctx)
	case license.LicenseTypeHardwareBound:
		return s.runHardwareBound(ctx)
	default:
		return fmt.Errorf("unsupported license type: %s", lic.LicenseType)
	}
}

// ---------------------------------------------------------------------------
// STANDARD license flow
// ---------------------------------------------------------------------------

func (s *Sentinel) runStandard(ctx context.Context) error {
	// Step 1: Register with the DRM server and obtain an in-memory session token.
	drmClient := drm.NewClient(*s.license.ServerURL, s.orgPubKey)
	regResp, err := drmClient.Register(drm.RegisterRequest{
		LicenseKey:      s.license.LicenseKey,
		Platform:        drm.DetectPlatform(),
		SoftwareVersion: s.config.Version,
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	if regResp.Status != "ACTIVE" {
		return fmt.Errorf("license is not active (status: %s) — shutting down", regResp.Status)
	}
	token := regResp.Token
	log.Printf("Registered with DRM server (token: %s...)", token[:8])

	// Step 2: Generate a session UUID for the IPC socket path.
	// This is local-only and is not sent to the server.
	sessionID := uuid.New().String()
	ipcSocketPath := ipc.SocketPath(sessionID)

	// Step 3: Launch software.
	proc, err := process.Launch(s.config.SoftwarePath, []string{
		"SENTINEL_IPC_SOCKET=" + ipcSocketPath,
	})
	if err != nil {
		return fmt.Errorf("launch software: %w", err)
	}
	s.process = proc

	// Step 4: Start IPC server.
	licenseInfo := &ipc.LicenseInfo{
		LicenseKey:  s.license.LicenseKey,
		LicenseType: string(s.license.LicenseType),
		ExpiryDate:  s.license.ExpiryDate,
		Features:    s.license.Features,
		OrgID:       s.license.OrgID,
		SoftwareID:  s.license.SoftwareID,
	}
	ipcSrv, err := ipc.NewServer(ipcSocketPath, licenseInfo)
	if err != nil {
		_ = proc.Stop()
		return fmt.Errorf("start IPC server: %w", err)
	}
	s.ipcServer = ipcSrv

	go ipcSrv.Serve(ctx) //nolint:errcheck

	// Step 5: Start anti-tamper monitor.
	go antitamper.NewMonitor(ipcSrv).Start(ctx)

	// Step 6: Start heartbeat loop.
	go s.heartbeatLoop(ctx, token, drmClient)

	// Step 7: Wait for software exit or shutdown signal.
	select {
	case <-proc.Exited():
		_ = ipcSrv.Close()
		return proc.Wait()
	case <-ctx.Done():
		_ = ipcSrv.Close()
		_ = proc.Stop()
		return nil
	}
}

// ---------------------------------------------------------------------------
// Heartbeat loop
// ---------------------------------------------------------------------------

func (s *Sentinel) heartbeatLoop(ctx context.Context, token string, drmClient *drm.Client) {
	interval := time.Duration(*s.license.HeartbeatIntervalMinutes) * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, err := drmClient.Heartbeat(token)
			if err != nil {
				log.Printf("Heartbeat failed: %v — shutting down", err)
				_ = s.process.Stop()
				return
			}

			if resp.Status != "ACTIVE" {
				log.Printf("License is not active (status: %s) — shutting down", resp.Status)
				_ = s.process.Stop()
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// HARDWARE_BOUND license flow
// ---------------------------------------------------------------------------

func (s *Sentinel) runHardwareBound(ctx context.Context) error {
	// Step 1: Collect hardware fingerprint.
	fingerprint, err := hardware.CollectFingerprint()
	if err != nil {
		return fmt.Errorf("hardware fingerprint collection failed: %w", err)
	}

	// Step 2: Compare with the fingerprint embedded in the license file.
	if fingerprint != *s.license.HardwareFingerprint {
		return fmt.Errorf("hardware fingerprint mismatch: this license is not valid for this machine")
	}

	// Step 3: Launch software. Use the fingerprint as the IPC socket name.
	ipcSocketPath := ipc.SocketPath(fingerprint)
	proc, err := process.Launch(s.config.SoftwarePath, []string{
		"SENTINEL_IPC_SOCKET=" + ipcSocketPath,
	})
	if err != nil {
		return fmt.Errorf("launch software: %w", err)
	}
	s.process = proc

	// Step 4: Start IPC server.
	licenseInfo := &ipc.LicenseInfo{
		LicenseKey:  s.license.LicenseKey,
		LicenseType: string(s.license.LicenseType),
		ExpiryDate:  s.license.ExpiryDate,
		Features:    s.license.Features,
		OrgID:       s.license.OrgID,
		SoftwareID:  s.license.SoftwareID,
	}
	ipcSrv, err := ipc.NewServer(ipcSocketPath, licenseInfo)
	if err != nil {
		_ = proc.Stop()
		return fmt.Errorf("start IPC server: %w", err)
	}
	s.ipcServer = ipcSrv

	go ipcSrv.Serve(ctx) //nolint:errcheck

	// Step 5: Start anti-tamper monitor.
	go antitamper.NewMonitor(ipcSrv).Start(ctx)

	// Step 6: Wait for software exit or signal. No heartbeat loop — fully offline.
	select {
	case <-proc.Exited():
		_ = ipcSrv.Close()
		return proc.Wait()
	case <-ctx.Done():
		_ = ipcSrv.Close()
		_ = proc.Stop()
		return nil
	}
}
