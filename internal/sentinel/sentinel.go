package sentinel

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	"github.com/google/uuid"

	"github.com/tusharlock10/sentinel-drm-client/internal/antitamper"
	"github.com/tusharlock10/sentinel-drm-client/internal/config"
	"github.com/tusharlock10/sentinel-drm-client/internal/crypto"
	"github.com/tusharlock10/sentinel-drm-client/internal/drm"
	"github.com/tusharlock10/sentinel-drm-client/internal/hardware"
	"github.com/tusharlock10/sentinel-drm-client/internal/ipc"
	"github.com/tusharlock10/sentinel-drm-client/internal/keystore"
	"github.com/tusharlock10/sentinel-drm-client/internal/license"
	"github.com/tusharlock10/sentinel-drm-client/internal/process"
	"github.com/tusharlock10/sentinel-drm-client/internal/state"
)

// Sentinel is the main orchestrator. It wires all components together and manages
// the full lifecycle of the license-enforced software process.
type Sentinel struct {
	config    *config.Config
	orgPubKey *ecdsa.PublicKey
	license   *license.LicensePayload
	stateMgr  *state.StateManager
	drmClient *drm.Client
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
	// Step 1: Init keystore — vault key tied to this machine's stable ID.
	machineID, err := hardware.GetMachineID()
	if err != nil {
		return fmt.Errorf("get machine ID for keystore: %w", err)
	}
	vaultKey := keystore.DeriveVaultKey(machineID)

	keystorePath, err := keystore.DefaultFilePath()
	if err != nil {
		return fmt.Errorf("get keystore path: %w", err)
	}
	ks, err := keystore.New(keystorePath, vaultKey)
	if err != nil {
		return fmt.Errorf("initialize keystore: %w", err)
	}

	// Step 2: Load or generate machine EC keypair.
	machineKey, machinePublicPEM, err := s.loadOrGenerateMachineKey(ks)
	if err != nil {
		return err
	}

	// Step 3: Load or create state.
	stateMgr, err := state.NewStateManager(ks)
	if err != nil {
		return fmt.Errorf("initialize state manager: %w", err)
	}
	st, err := stateMgr.Load()
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	if st == nil {
		st = &state.State{
			MachineID:             uuid.New().String(),
			Activated:             false,
			LicenseKey:            s.license.LicenseKey,
			GraceRemainingSeconds: int64(*s.license.HeartbeatGracePeriodDays) * 86400,
		}
		if err := stateMgr.Save(st); err != nil {
			return fmt.Errorf("save initial state: %w", err)
		}
	}

	// Step 4: License key change detection — reset activation if the user switched license files.
	if st.LicenseKey != s.license.LicenseKey {
		st.Activated = false
		st.LicenseKey = s.license.LicenseKey
		st.GraceRemainingSeconds = int64(*s.license.HeartbeatGracePeriodDays) * 86400
		st.GraceExhausted = false
		if err := stateMgr.Save(st); err != nil {
			return fmt.Errorf("save state after license key change: %w", err)
		}
	}

	// Step 5: Create DRM client. Server URL comes from the license payload.
	drmClient := drm.NewClient(*s.license.ServerURL, st.MachineID, machineKey, s.orgPubKey)

	// Step 6: Activation (if needed).
	if !st.Activated {
		_, err := drmClient.Activate(drm.ActivateRequest{
			LicenseKey:          s.license.LicenseKey,
			MachineID:           st.MachineID,
			MachinePublicKeyPEM: machinePublicPEM,
			Platform:            drm.DetectPlatform(),
			SoftwareVersion:     s.config.Version,
		})
		if err != nil {
			return fmt.Errorf("activation failed: %w", err)
		}
		st.Activated = true
		st.LastHeartbeatSuccess = time.Now().Unix()
		if err := stateMgr.Save(st); err != nil {
			return fmt.Errorf("save state after activation: %w", err)
		}
	}

	// Step 7: Mandatory startup heartbeat. STANDARD licenses must contact the server on
	// every startup to prevent grace period abuse via restart cycling.
	hbResp, err := drmClient.Heartbeat(drm.HeartbeatRequest{
		LicenseKey:      s.license.LicenseKey,
		MachineID:       st.MachineID,
		SoftwareVersion: s.config.Version,
	})
	if err != nil {
		if drm.IsConnectionError(err) {
			if st.GraceExhausted {
				return errors.New("server unreachable and grace period exhausted — cannot start")
			}
			if st.GraceRemainingSeconds <= 0 {
				st.GraceExhausted = true
				_ = stateMgr.Save(st)
				return errors.New("server unreachable and grace period exhausted — cannot start")
			}
			log.Printf("WARNING: Server unreachable, operating under grace period (%d seconds remaining)",
				st.GraceRemainingSeconds)
		} else {
			return fmt.Errorf("startup heartbeat failed: %w", err)
		}
	} else {
		if err := s.processHeartbeatResponse(hbResp, st, stateMgr, drmClient); err != nil {
			return err
		}
	}

	// Step 8: Launch software.
	ipcSocketPath := ipc.SocketPath(st.MachineID)
	proc, err := process.Launch(s.config.SoftwarePath, []string{
		"SENTINEL_IPC_SOCKET=" + ipcSocketPath,
	})
	if err != nil {
		return fmt.Errorf("launch software: %w", err)
	}
	s.process = proc

	// Step 9: Start IPC server.
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

	// Step 10: Start anti-tamper monitor.
	go antitamper.NewMonitor(ipcSrv).Start(ctx)

	// Step 11: Start heartbeat loop.
	go s.heartbeatLoop(ctx, st, stateMgr, drmClient)

	// Step 12: Wait for software exit or shutdown signal.
	select {
	case <-proc.Exited():
		s.cleanup(st, stateMgr)
		return proc.Wait()
	case <-ctx.Done():
		s.cleanup(st, stateMgr)
		_ = proc.Stop()
		return nil
	}
}

// loadOrGenerateMachineKey retrieves the machine EC private key from the keystore.
// If none exists, a new EC P-256 keypair is generated and stored.
// When loading an existing key, the raw PEM bytes are protected with a memguard
// LockedBuffer to prevent the key material from being swapped to disk.
// Returns the parsed private key and the PEM-encoded public key string.
func (s *Sentinel) loadOrGenerateMachineKey(ks keystore.Keystore) (*ecdsa.PrivateKey, string, error) {
	privPEM, err := ks.Retrieve(keystore.KeyMachinePrivateKey)
	if errors.Is(err, keystore.ErrNotFound) {
		// First run — generate a new keypair.
		privKey, genErr := crypto.GenerateECKeyPair()
		if genErr != nil {
			return nil, "", fmt.Errorf("generate machine EC keypair: %w", genErr)
		}
		privPEMBytes, genErr := crypto.ECPrivateKeyToPEM(privKey)
		if genErr != nil {
			return nil, "", fmt.Errorf("encode machine private key: %w", genErr)
		}
		if storeErr := ks.Store(keystore.KeyMachinePrivateKey, privPEMBytes); storeErr != nil {
			return nil, "", fmt.Errorf("store machine private key: %w", storeErr)
		}
		pubPEM, genErr := crypto.ECPublicKeyToPEM(&privKey.PublicKey)
		if genErr != nil {
			return nil, "", fmt.Errorf("encode machine public key: %w", genErr)
		}
		return privKey, pubPEM, nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("retrieve machine private key: %w", err)
	}

	// Protect the raw PEM bytes in locked memory — prevents swapping to disk and
	// clears the bytes on function exit. The original slice is zeroed by memguard.
	privPEMBuf := memguard.NewBufferFromBytes(privPEM)
	defer privPEMBuf.Destroy()

	privKey, err := crypto.ParseECPrivateKeyPEM(privPEMBuf.Bytes())
	if err != nil {
		return nil, "", fmt.Errorf("parse machine private key: %w", err)
	}
	pubPEM, err := crypto.ECPublicKeyToPEM(&privKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("encode machine public key: %w", err)
	}
	return privKey, pubPEM, nil
}

// ---------------------------------------------------------------------------
// Heartbeat loop
// ---------------------------------------------------------------------------

func (s *Sentinel) heartbeatLoop(ctx context.Context, st *state.State, stateMgr *state.StateManager, drmClient *drm.Client) {
	interval := time.Duration(*s.license.HeartbeatIntervalMinutes) * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, err := drmClient.Heartbeat(drm.HeartbeatRequest{
				LicenseKey:      s.license.LicenseKey,
				MachineID:       st.MachineID,
				SoftwareVersion: s.config.Version,
			})
			if err != nil {
				if drm.IsConnectionError(err) {
					consumeGrace(st, stateMgr, interval)
					if isGraceExhausted(st) {
						log.Println("Grace period exhausted — shutting down")
						_ = s.process.Stop()
						return
					}
					log.Printf("Heartbeat failed (connection error), grace remaining: %ds", st.GraceRemainingSeconds)
				} else {
					// Server responded with an error — don't consume grace, retry next interval.
					log.Printf("Heartbeat error: %v", err)
				}
				continue
			}

			st.LastHeartbeatSuccess = time.Now().Unix()
			if err := stateMgr.Save(st); err != nil {
				log.Printf("Failed to save state after heartbeat: %v", err)
			}

			if err := s.processHeartbeatResponse(resp, st, stateMgr, drmClient); err != nil {
				log.Printf("Heartbeat response requires shutdown: %v", err)
				_ = s.process.Stop()
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Grace period helpers
// ---------------------------------------------------------------------------

func consumeGrace(st *state.State, stateMgr *state.StateManager, interval time.Duration) {
	consumed := int64(interval.Seconds())
	st.GraceRemainingSeconds -= consumed
	if st.GraceRemainingSeconds < 0 {
		st.GraceRemainingSeconds = 0
	}
	if st.GraceRemainingSeconds == 0 {
		st.GraceExhausted = true
	}
	_ = stateMgr.Save(st)
}

func isGraceExhausted(st *state.State) bool {
	if st.GraceExhausted {
		return true
	}
	return st.GraceRemainingSeconds <= 0
}

// ---------------------------------------------------------------------------
// Heartbeat response handler
// ---------------------------------------------------------------------------

func (s *Sentinel) processHeartbeatResponse(
	resp *drm.HeartbeatResponse,
	st *state.State,
	stateMgr *state.StateManager,
	drmClient *drm.Client,
) error {
	switch resp.Status {
	case "ACTIVE":
		return nil

	case "DECOMMISSION_PENDING":
		log.Println("Decommission requested — acknowledging and shutting down")
		_, err := drmClient.DecommissionAck(drm.DecommissionAckRequest{
			LicenseKey: s.license.LicenseKey,
			MachineID:  st.MachineID,
		})
		if err != nil {
			log.Printf("Decommission ack failed: %v", err)
		}
		if err := stateMgr.Delete(); err != nil {
			log.Printf("Failed to delete state file: %v", err)
		}
		return fmt.Errorf("machine decommissioned")

	case "REVOKED":
		return fmt.Errorf("license has been revoked")

	case "EXPIRED":
		return fmt.Errorf("license has expired")

	case "SUSPENDED":
		return fmt.Errorf("license is suspended — contact your vendor")

	default:
		return fmt.Errorf("unexpected license status: %s", resp.Status)
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

	// Step 3: Launch software. Use the fingerprint as the machine ID for IPC socket naming.
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

	// Step 6: Wait for software exit or shutdown signal. No heartbeat loop — fully offline.
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
// Cleanup
// ---------------------------------------------------------------------------

func (s *Sentinel) cleanup(st *state.State, stateMgr *state.StateManager) {
	if s.ipcServer != nil {
		_ = s.ipcServer.Close()
	}
	if st != nil && stateMgr != nil {
		_ = stateMgr.Save(st)
	}
}
