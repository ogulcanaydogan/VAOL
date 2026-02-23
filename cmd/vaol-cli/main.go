// Command vaol is the CLI tool for the Verifiable AI Output Ledger.
// It provides commands to initialize, verify, inspect, export, and manage keys.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/export"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
	"github.com/ogulcanaydogan/vaol/pkg/verifier"
	"github.com/spf13/cobra"
)

// Build-time variables injected via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:     "vaol",
		Short:   "VAOL — Verifiable AI Output Ledger CLI",
		Long:    "Cryptographically verify, inspect, and export AI inference decision records.",
		Version: fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
	}

	root.AddCommand(
		newInitCmd(),
		newVerifyCmd(),
		newInspectCmd(),
		newExportCmd(),
		newLifecycleCmd(),
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
	var revocationsFile string
	var sigstoreVerify bool
	var sigstoreOIDCIssuer string
	var sigstoreRekorURL string
	var sigstoreRekorRequired bool
	var transcriptJSONPath string
	var reportJSONPath string
	var reportMarkdownPath string
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

			verifiers, err := buildVerificationVerifiers(
				pubKeyPath,
				sigstoreVerify,
				sigstoreOIDCIssuer,
				sigstoreRekorURL,
				sigstoreRekorRequired,
			)
			if err != nil {
				return err
			}

			v := verifier.New(verifiers...)
			if revocationsFile != "" {
				rules, err := verifier.LoadRevocationListFile(revocationsFile)
				if err != nil {
					return fmt.Errorf("loading revocations file: %w", err)
				}
				if err := v.SetRevocations(rules); err != nil {
					return fmt.Errorf("applying revocations: %w", err)
				}
			}

			selectedProfile := verifier.Profile(profile)
			if selectedProfile == "" {
				selectedProfile = verifier.ProfileBasic
			}

			result, err := v.VerifyBundle(context.Background(), bundle, selectedProfile)
			if err != nil {
				return fmt.Errorf("verifying bundle: %w", err)
			}

			if transcriptJSONPath != "" {
				transcript, err := verifier.NewBundleTranscript(selectedProfile, bundle, result)
				if err != nil {
					return fmt.Errorf("building verification transcript: %w", err)
				}
				raw, err := transcript.ToJSON()
				if err != nil {
					return fmt.Errorf("serializing verification transcript: %w", err)
				}
				if err := os.WriteFile(transcriptJSONPath, raw, 0644); err != nil {
					return fmt.Errorf("writing verification transcript: %w", err)
				}
			}

			if reportJSONPath != "" || reportMarkdownPath != "" {
				report := verifier.NewReport("VAOL Bundle Verification Report", *result)
				if reportJSONPath != "" {
					raw, err := report.ToJSON()
					if err != nil {
						return fmt.Errorf("serializing verification report json: %w", err)
					}
					if err := os.WriteFile(reportJSONPath, raw, 0644); err != nil {
						return fmt.Errorf("writing verification report json: %w", err)
					}
				}
				if reportMarkdownPath != "" {
					if err := os.WriteFile(reportMarkdownPath, []byte(report.ToMarkdown()), 0644); err != nil {
						return fmt.Errorf("writing verification report markdown: %w", err)
					}
				}
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
			fmt.Printf("  Manifest valid:  %v\n", result.ManifestValid)

			if result.InvalidRecords > 0 || result.Summary != "VERIFICATION PASSED" {
				fmt.Println("\nVERIFICATION FAILED")
				return fmt.Errorf("verification failed")
			}
			fmt.Println("\nVERIFICATION PASSED")
			return nil
		},
	}
	cmd.Flags().StringVar(&pubKeyPath, "public-key", "", "Ed25519 public key PEM for signature verification")
	cmd.Flags().StringVar(&profile, "profile", string(verifier.ProfileBasic), "verification profile: basic, strict, fips")
	cmd.Flags().StringVar(&revocationsFile, "revocations-file", "", "path to revocation list JSON with keyid/effective_at rules")
	cmd.Flags().BoolVar(&sigstoreVerify, "sigstore-verify", false, "enable Sigstore signature verification")
	cmd.Flags().StringVar(&sigstoreOIDCIssuer, "sigstore-oidc-issuer", "https://oauth2.sigstore.dev/auth", "expected Sigstore OIDC issuer")
	cmd.Flags().StringVar(&sigstoreRekorURL, "sigstore-rekor-url", "https://rekor.sigstore.dev", "Sigstore Rekor URL")
	cmd.Flags().BoolVar(&sigstoreRekorRequired, "sigstore-rekor-required", false, "require Rekor entry verification for Sigstore signatures")
	cmd.Flags().StringVar(&transcriptJSONPath, "transcript-json", "", "write deterministic verification transcript to JSON file")
	cmd.Flags().StringVar(&reportJSONPath, "report-json", "", "write verification report JSON")
	cmd.Flags().StringVar(&reportMarkdownPath, "report-markdown", "", "write verification report Markdown")
	return cmd
}

func newVerifyRecordCmd() *cobra.Command {
	var pubKeyPath string
	var profile string
	var revocationsFile string
	var sigstoreVerify bool
	var sigstoreOIDCIssuer string
	var sigstoreRekorURL string
	var sigstoreRekorRequired bool
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

			verifiers, err := buildVerificationVerifiers(
				pubKeyPath,
				sigstoreVerify,
				sigstoreOIDCIssuer,
				sigstoreRekorURL,
				sigstoreRekorRequired,
			)
			if err != nil {
				return err
			}

			v := verifier.New(verifiers...)
			if revocationsFile != "" {
				rules, err := verifier.LoadRevocationListFile(revocationsFile)
				if err != nil {
					return fmt.Errorf("loading revocations file: %w", err)
				}
				if err := v.SetRevocations(rules); err != nil {
					return fmt.Errorf("applying revocations: %w", err)
				}
			}
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
				return fmt.Errorf("verification failed")
			}
			fmt.Println("\nVERIFICATION PASSED")
			return nil
		},
	}
	cmd.Flags().StringVar(&pubKeyPath, "public-key", "", "Ed25519 public key PEM")
	cmd.Flags().StringVar(&profile, "profile", string(verifier.ProfileBasic), "verification profile: basic, strict, fips")
	cmd.Flags().StringVar(&revocationsFile, "revocations-file", "", "path to revocation list JSON with keyid/effective_at rules")
	cmd.Flags().BoolVar(&sigstoreVerify, "sigstore-verify", false, "enable Sigstore signature verification")
	cmd.Flags().StringVar(&sigstoreOIDCIssuer, "sigstore-oidc-issuer", "https://oauth2.sigstore.dev/auth", "expected Sigstore OIDC issuer")
	cmd.Flags().StringVar(&sigstoreRekorURL, "sigstore-rekor-url", "https://rekor.sigstore.dev", "Sigstore Rekor URL")
	cmd.Flags().BoolVar(&sigstoreRekorRequired, "sigstore-rekor-required", false, "require Rekor entry verification for Sigstore signatures")
	return cmd
}

func buildVerificationVerifiers(
	pubKeyPath string,
	sigstoreVerify bool,
	sigstoreOIDCIssuer string,
	sigstoreRekorURL string,
	sigstoreRekorRequired bool,
) ([]signer.Verifier, error) {
	var verifiers []signer.Verifier

	if pubKeyPath != "" {
		pubKey, err := signer.LoadPublicKeyPEM(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		verifiers = append(verifiers, signer.NewEd25519Verifier(pubKey))
	}

	if sigstoreVerify {
		cfg := signer.DefaultSigstoreConfig()
		if sigstoreOIDCIssuer != "" {
			cfg.OIDCIssuer = sigstoreOIDCIssuer
		}
		if sigstoreRekorURL != "" {
			cfg.RekorURL = sigstoreRekorURL
		}
		cfg.RequireRekor = sigstoreRekorRequired
		verifiers = append(verifiers, signer.NewSigstoreVerifier(cfg))
	}

	return verifiers, nil
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

func newLifecycleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lifecycle",
		Short: "Run privacy lifecycle maintenance jobs",
	}
	cmd.AddCommand(
		newLifecycleRetentionCmd(),
		newLifecycleRotateKeysCmd(),
		newLifecycleListTombstonesCmd(),
		newLifecycleListKeyRotationsCmd(),
	)
	return cmd
}

func newLifecycleRetentionCmd() *cobra.Command {
	var dsn string
	var before string
	var limit int
	var reason string

	cmd := &cobra.Command{
		Use:   "retention",
		Short: "Delete expired encrypted payloads and emit tombstones",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				return fmt.Errorf("--dsn is required")
			}
			runBefore := time.Now().UTC()
			if before != "" {
				parsed, err := time.Parse(time.RFC3339, before)
				if err != nil {
					return fmt.Errorf("parsing --before: %w", err)
				}
				runBefore = parsed.UTC()
			}

			st, err := store.Connect(context.Background(), dsn)
			if err != nil {
				return fmt.Errorf("connecting to postgres: %w", err)
			}
			defer st.Close()

			report, err := store.RunRetentionJob(context.Background(), st, runBefore, limit, reason)
			if err != nil {
				return fmt.Errorf("running retention job: %w", err)
			}
			raw, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return fmt.Errorf("serializing retention report: %w", err)
			}
			fmt.Println(string(raw))
			return nil
		},
	}
	cmd.Flags().StringVar(&dsn, "dsn", "", "PostgreSQL DSN")
	cmd.Flags().StringVar(&before, "before", "", "retention cutoff timestamp (RFC3339, default now)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum rows to process")
	cmd.Flags().StringVar(&reason, "reason", "retention_expired", "deletion reason")
	return cmd
}

func newLifecycleRotateKeysCmd() *cobra.Command {
	var dsn string
	var oldKeyID string
	var newKeyID string
	var limit int

	cmd := &cobra.Command{
		Use:   "rotate-keys",
		Short: "Rotate encrypted payload key metadata and persist key-rotation evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				return fmt.Errorf("--dsn is required")
			}
			if oldKeyID == "" || newKeyID == "" {
				return fmt.Errorf("--old-key and --new-key are required")
			}

			st, err := store.Connect(context.Background(), dsn)
			if err != nil {
				return fmt.Errorf("connecting to postgres: %w", err)
			}
			defer st.Close()

			report, err := store.RunKeyRotationJob(context.Background(), st, oldKeyID, newKeyID, limit)
			if err != nil {
				return fmt.Errorf("running key rotation job: %w", err)
			}
			raw, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return fmt.Errorf("serializing key rotation report: %w", err)
			}
			fmt.Println(string(raw))
			return nil
		},
	}
	cmd.Flags().StringVar(&dsn, "dsn", "", "PostgreSQL DSN")
	cmd.Flags().StringVar(&oldKeyID, "old-key", "", "previous encryption key ID")
	cmd.Flags().StringVar(&newKeyID, "new-key", "", "new encryption key ID")
	cmd.Flags().IntVar(&limit, "limit", 1000, "maximum rows to process")
	return cmd
}

func newLifecycleListTombstonesCmd() *cobra.Command {
	var dsn string
	var tenantID string
	var limit int

	cmd := &cobra.Command{
		Use:   "list-tombstones",
		Short: "List payload tombstones",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				return fmt.Errorf("--dsn is required")
			}
			st, err := store.Connect(context.Background(), dsn)
			if err != nil {
				return fmt.Errorf("connecting to postgres: %w", err)
			}
			defer st.Close()

			tombstones, err := st.ListPayloadTombstones(context.Background(), tenantID, limit)
			if err != nil {
				return fmt.Errorf("listing tombstones: %w", err)
			}
			raw, err := json.MarshalIndent(tombstones, "", "  ")
			if err != nil {
				return fmt.Errorf("serializing tombstones: %w", err)
			}
			fmt.Println(string(raw))
			return nil
		},
	}
	cmd.Flags().StringVar(&dsn, "dsn", "", "PostgreSQL DSN")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "tenant filter (optional)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum rows")
	return cmd
}

func newLifecycleListKeyRotationsCmd() *cobra.Command {
	var dsn string
	var limit int

	cmd := &cobra.Command{
		Use:   "list-key-rotations",
		Short: "List key-rotation evidence events",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dsn == "" {
				return fmt.Errorf("--dsn is required")
			}
			st, err := store.Connect(context.Background(), dsn)
			if err != nil {
				return fmt.Errorf("connecting to postgres: %w", err)
			}
			defer st.Close()

			events, err := st.ListKeyRotationEvents(context.Background(), limit)
			if err != nil {
				return fmt.Errorf("listing key-rotation events: %w", err)
			}
			raw, err := json.MarshalIndent(events, "", "  ")
			if err != nil {
				return fmt.Errorf("serializing key-rotation events: %w", err)
			}
			fmt.Println(string(raw))
			return nil
		},
	}
	cmd.Flags().StringVar(&dsn, "dsn", "", "PostgreSQL DSN")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum rows")
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
