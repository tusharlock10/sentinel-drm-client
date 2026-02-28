package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tusharlock10/sentinel-drm-client/internal/config"
	"github.com/tusharlock10/sentinel-drm-client/internal/crypto"
	"github.com/tusharlock10/sentinel-drm-client/internal/sentinel"
)

// orgPublicKeyPEM is the EC P-256 public key of the organization, embedded at build time.
// Set via: -ldflags "-X main.orgPublicKeyPEM=<PEM string>"
// An empty value means the binary was built without embedding the org key.
var orgPublicKeyPEM string

// version is set at build time via -ldflags "-X main.version=<version>"
var version string

func main() {
	rootCmd := &cobra.Command{
		Use:     "sentinel",
		Short:   "Sentinel DRM Client — enforces software licensing",
		Version: version,
		RunE:    run,
	}

	rootCmd.Flags().String("license", "", "Path to the .lic license file")
	rootCmd.Flags().String("software", "", "Path to the software binary to launch")

	if err := rootCmd.MarkFlagRequired("license"); err != nil {
		fmt.Fprintf(os.Stderr, "internal error: %v\n", err)
		os.Exit(1)
	}
	if err := rootCmd.MarkFlagRequired("software"); err != nil {
		fmt.Fprintf(os.Stderr, "internal error: %v\n", err)
		os.Exit(1)
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	if orgPublicKeyPEM == "" {
		return fmt.Errorf("this binary was built without an embedded organization public key; rebuild with -ldflags \"-X main.orgPublicKeyPEM=...\"")
	}

	// The Makefile embeds the PEM with literal \n to avoid shell quoting issues.
	// Restore real newlines before parsing.
	orgPublicKeyPEM = strings.ReplaceAll(orgPublicKeyPEM, `\n`, "\n")

	orgPubKey, err := crypto.ParseECPublicKeyPEM(orgPublicKeyPEM)
	if err != nil {
		return fmt.Errorf("invalid embedded organization public key: %w", err)
	}

	licensePath, _ := cmd.Flags().GetString("license")
	softwarePath, _ := cmd.Flags().GetString("software")

	cfg := &config.Config{
		LicensePath:  licensePath,
		SoftwarePath: softwarePath,
		Version:      version,
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	ctx, cancel := sentinel.SetupSignalHandler()
	defer cancel()

	s := sentinel.New(cfg, orgPubKey)
	return s.Run(ctx)
}
