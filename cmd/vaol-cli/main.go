// Command vaol is the CLI tool for the Verifiable AI Output Ledger.
// It provides commands to initialize, verify, inspect, export, and manage keys.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yapay-ai/vaol/pkg/export"
	"github.com/yapay-ai/vaol/pkg/signer"
	"github.com/yapay-ai/vaol/pkg/verifier"
)

var version = "0.1.0"

func main() {
	root := &cobra.Command{
		Use:     "vaol",
		Short:   "VAOL — Verifiable AI Output Ledger CLI",
		Long:    "Cryptographically verify, inspect, and export AI inference decision records.",
		Version: version,
	}

	root.AddCommand(
		newInitCmd(),
		newVerifyCmd(),
		newInspectCmd(),
		newExportCmd(),
		newKeysCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newInitCmd() *cobra.Command {
	var keyDir string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a VAOL configuration directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyDir == "" {
				home, _ := os.UserHomeDir()
				keyDir = home + "/.vaol"
			}

			if err := os.MkdirAll(keyDir+"/keys", 0700); err != nil {
				return fmt.Errorf("creating key directory: %w", err)
			}

			fmt.Printf("Initialized VAOL directory at %s\n", keyDir)
			fmt.Println("Run 'vaol keys generate' to create a signing key pair.")
			return nil
		},
	}
	cmd.Flags().StringVar(&keyDir, "dir", "", "VAOL config directory (default: ~/.vaol)")
	return cmd
}

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify records or audit bundles",
	}

	cmd.AddCommand(newVerifyBundleCmd())
	cmd.AddCommand(newVerifyRecordCmd())

	return cmd
}

func newVerifyBundleCmd() *cobra.Command {
	var pubKeyPath string
	var profile string
	cmd := &cobra.Command{
		Use:   "bundle <file>",
		Short: "Verify an exported audit bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundlePath := args[0]

			bundle, err := export.ReadJSON(bundlePath)
			if err != nil {
				return fmt.Errorf("reading bundle: %w", err)
			}

			// Load verifier
			var verifiers []signer.Verifier
			if pubKeyPath != "" {
				pubKey, err := signer.LoadPublicKeyPEM(pubKeyPath)
				if err != nil {
					return fmt.Errorf("loading public key: %w", err)
				}
				verifiers = append(verifiers, signer.NewEd25519Verifier(pubKey))
			}

			v := verifier.New(verifiers...)

			selectedProfile := verifier.Profile(profile)
			if selectedProfile == "" {
				selectedProfile = verifier.ProfileBasic
			}

			result, err := v.VerifyBundle(context.Background(), bundle, selectedProfile)
			if err != nil {
				return fmt.Errorf("verifying bundle: %w", err)
			}

			for _, rec := range result.Results {
				if rec.Valid {
					continue
				}
				for _, check := range rec.Checks {
					if !check.Passed {
						fmt.Fprintf(os.Stderr, "  FAIL  request_id=%s check=%s error=%s\n",
							rec.RequestID, check.Name, check.Error)
					}
				}
			}

			fmt.Println()
			fmt.Printf("Bundle verification complete:\n")
			fmt.Printf("  Total records:   %d\n", result.TotalRecords)
			fmt.Printf("  Valid:           %d\n", result.ValidRecords)
			fmt.Printf("  Invalid:         %d\n", result.InvalidRecords)
			fmt.Printf("  Chain intact:    %v\n", result.ChainIntact)
			fmt.Printf("  Merkle valid:    %v\n", result.MerkleValid)
			fmt.Printf("  Checkpoint valid:%v\n", result.CheckpointValid)

			if result.InvalidRecords > 0 || result.Summary != "VERIFICATION PASSED" {
				fmt.Println("\nVERIFICATION FAILED")
				os.Exit(1)
			}
			fmt.Println("\nVERIFICATION PASSED")
			return nil
		},
	}
	cmd.Flags().StringVar(&pubKeyPath, "public-key", "", "Ed25519 public key PEM for signature verification")
	cmd.Flags().StringVar(&profile, "profile", string(verifier.ProfileBasic), "verification profile: basic, strict, fips")
	return cmd
}

func newVerifyRecordCmd() *cobra.Command {
	var pubKeyPath string
	var profile string
	cmd := &cobra.Command{
		Use:   "record <file>",
		Short: "Verify a single DSSE envelope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}

			var env signer.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				return fmt.Errorf("parsing envelope: %w", err)
			}

			var verifiers []signer.Verifier
			if pubKeyPath != "" {
				pubKey, err := signer.LoadPublicKeyPEM(pubKeyPath)
				if err != nil {
					return fmt.Errorf("loading public key: %w", err)
				}
				verifiers = append(verifiers, signer.NewEd25519Verifier(pubKey))
			}

			v := verifier.New(verifiers...)
			selectedProfile := verifier.Profile(profile)
			if selectedProfile == "" {
				selectedProfile = verifier.ProfileBasic
			}

			result, err := v.VerifyEnvelopeWithProfile(context.Background(), &env, selectedProfile)
			if err != nil {
				return fmt.Errorf("verification error: %w", err)
			}

			for _, check := range result.Checks {
				status := "PASS"
				if !check.Passed {
					status = "FAIL"
				}
				fmt.Printf("  [%s] %s", status, check.Name)
				if check.Details != "" {
					fmt.Printf(": %s", check.Details)
				}
				if check.Error != "" {
					fmt.Printf(": %s", check.Error)
				}
				fmt.Println()
			}

			if !result.Valid {
				fmt.Println("\nVERIFICATION FAILED")
				os.Exit(1)
			}
			fmt.Println("\nVERIFICATION PASSED")
			return nil
		},
	}
	cmd.Flags().StringVar(&pubKeyPath, "public-key", "", "Ed25519 public key PEM")
	cmd.Flags().StringVar(&profile, "profile", string(verifier.ProfileBasic), "verification profile: basic, strict, fips")
	return cmd
}

func newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <file>",
		Short: "Inspect a DSSE envelope and show its contents",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}

			var env signer.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				return fmt.Errorf("parsing envelope: %w", err)
			}

			payload, err := signer.ExtractPayload(&env)
			if err != nil {
				return fmt.Errorf("extracting payload: %w", err)
			}

			fmt.Printf("Payload Type: %s\n", env.PayloadType)
			fmt.Printf("Signatures:   %d\n", len(env.Signatures))
			for i, sig := range env.Signatures {
				fmt.Printf("  [%d] keyid=%s timestamp=%s\n", i, sig.KeyID, sig.Timestamp)
			}
			fmt.Println()

			// Pretty-print the payload
			var pretty json.RawMessage = payload
			out, err := json.MarshalIndent(pretty, "", "  ")
			if err != nil {
				fmt.Printf("Payload (raw):\n%s\n", string(payload))
			} else {
				fmt.Printf("Payload:\n%s\n", string(out))
			}

			return nil
		},
	}
	return cmd
}

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export records from a VAOL server as an audit bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Export requires a running VAOL server. Use the REST API:")
			fmt.Println("  curl -X POST http://localhost:8080/v1/export \\")
			fmt.Println("    -H 'Content-Type: application/json' \\")
			fmt.Println("    -d '{\"tenant_id\": \"...\", \"after\": \"...\", \"before\": \"...\"}' \\")
			fmt.Println("    -o audit-bundle.json")
			return nil
		},
	}
	return cmd
}

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage signing keys",
	}

	cmd.AddCommand(newKeysGenerateCmd())
	return cmd
}

func newKeysGenerateCmd() *cobra.Command {
	var outputDir string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new Ed25519 signing key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputDir == "" {
				home, _ := os.UserHomeDir()
				outputDir = home + "/.vaol/keys"
			}

			if err := os.MkdirAll(outputDir, 0700); err != nil {
				return fmt.Errorf("creating output directory: %w", err)
			}

			s, err := signer.GenerateEd25519Signer()
			if err != nil {
				return fmt.Errorf("generating key: %w", err)
			}

			privPath := outputDir + "/vaol-signing.pem"
			pubPath := outputDir + "/vaol-signing.pub"

			if err := signer.SavePrivateKeyPEM(s.PrivateKey(), privPath); err != nil {
				return fmt.Errorf("saving private key: %w", err)
			}
			if err := signer.SavePublicKeyPEM(s.PublicKey(), pubPath); err != nil {
				return fmt.Errorf("saving public key: %w", err)
			}

			fmt.Printf("Key pair generated:\n")
			fmt.Printf("  Private key: %s\n", privPath)
			fmt.Printf("  Public key:  %s\n", pubPath)
			fmt.Printf("  Key ID:      %s\n", s.KeyID())
			fmt.Printf("\nKeep the private key secure. Never commit it to version control.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&outputDir, "output", "", "output directory (default: ~/.vaol/keys)")
	return cmd
}
