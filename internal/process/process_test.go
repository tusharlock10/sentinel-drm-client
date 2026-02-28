package process

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestMain intercepts test binary execution so the binary can be re-launched as a
// controlled subprocess in process lifecycle tests. Each PROCESS_TEST_HELPER value
// causes the subprocess to behave deterministically without running any tests.
func TestMain(m *testing.M) {
	switch os.Getenv("PROCESS_TEST_HELPER") {
	case "exit0":
		os.Exit(0)
	case "exit1":
		os.Exit(1)
	case "sleep":
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestLaunchAndWait launches the test binary itself (configured to exit immediately)
// and verifies that Wait returns nil for a clean exit.
func TestLaunchAndWait(t *testing.T) {
	m, err := Launch(os.Args[0], []string{"PROCESS_TEST_HELPER=exit0"})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if err := m.Wait(); err != nil {
		t.Fatalf("Wait: expected nil exit error, got %v", err)
	}
}

// TestExitedChannel verifies that the channel from Exited() is closed when the process exits.
func TestExitedChannel(t *testing.T) {
	m, err := Launch(os.Args[0], []string{"PROCESS_TEST_HELPER=exit0"})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	select {
	case <-m.Exited():
		// ok
	case <-time.After(5 * time.Second):
		t.Fatal("Exited() channel was not closed within 5 seconds")
	}
}

// TestNonZeroExitPreserved verifies that a non-zero exit code is propagated by Wait.
func TestNonZeroExitPreserved(t *testing.T) {
	m, err := Launch(os.Args[0], []string{"PROCESS_TEST_HELPER=exit1"})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if err := m.Wait(); err == nil {
		t.Fatal("expected non-nil error for exit code 1, got nil")
	}
}

// TestStop launches a long-sleeping subprocess and verifies Stop terminates it promptly.
func TestStop(t *testing.T) {
	m, err := Launch(os.Args[0], []string{"PROCESS_TEST_HELPER=sleep"})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- m.Stop()
	}()

	select {
	case <-done:
		// Stop returned; process terminated.
	case <-time.After(15 * time.Second):
		t.Fatal("Stop did not return within 15 seconds")
	}
}

// TestVerifyBinaryChecksum verifies correct SHA-256 matching and mismatch detection.
func TestVerifyBinaryChecksum(t *testing.T) {
	content := []byte("sentinel-drm checksum test content")

	f, err := os.CreateTemp("", "sentinel-checksum-*.bin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	sum := sha256.Sum256(content)
	expected := fmt.Sprintf("%x", sum)

	if err := VerifyBinaryChecksum(f.Name(), expected); err != nil {
		t.Fatalf("VerifyBinaryChecksum: unexpected error: %v", err)
	}

	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifyBinaryChecksum(f.Name(), wrongChecksum); err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
}
