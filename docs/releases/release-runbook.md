# VAOL Release Runbook

This runbook defines the release flow for VAOL and records repository-mode constraints that affect enforcement.

## Scope

- Tag-driven release workflow: `.github/workflows/release.yml` (`v*` tags).
- Artifact publisher: GoReleaser (`.goreleaser.yml`).
- CI quality gate: `.github/workflows/ci.yml`.

## Standard Release Steps

1. Ensure `main` is clean and synced:
   - `git switch main`
   - `git pull --ff-only`
2. Verify CI is green on the merge commit:
   - `gh run list --workflow CI --branch main --limit 1`
3. Create and push the release tag:
   - `git tag -a vX.Y.Z -m "vX.Y.Z"`
   - `git push origin refs/tags/vX.Y.Z`
4. Confirm release workflow completion:
   - `gh run list --workflow Release --limit 1`
5. Verify release object:
   - `gh api repos/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tags/vX.Y.Z`

## Post-Release Smoke Validation

1. Verify checksums from release assets.
2. Run released binaries (`vaol`, `vaol-server`, `vaol-proxy`) with `--help` sanity checks.
3. Run reproducible demo with released binaries:
   - `VAOL_DEMO_SKIP_BUILD=1 VAOL_DEMO_BIN_DIR=<release-bin-dir> ./scripts/demo_auditor.sh`
4. Verify container image pull/run smoke:
   - `docker pull ghcr.io/ogulcanaydogan/vaol-server:vX.Y.Z`
   - `docker pull ghcr.io/ogulcanaydogan/vaol-proxy:vX.Y.Z`

## Private Repository Constraints (User-Owned)

These constraints were observed on February 20, 2026:

1. Branch protection and repository rulesets API can return `403` on private user-owned repositories without GitHub Pro.
2. Artifact attestation persistence can be unavailable for this repository mode.

Current workflow handling:

- Attestation step is conditionally skipped for user-owned private repositories.
- Release continues with signed artifacts, checksums, and SBOM artifact publication.

## Manual Merge Gate (When Branch Protection Is Unavailable)

Before merging any PR to `main`:

1. CI workflow for the PR branch must be `completed/success`.
2. Auditor demo integration job must be green.
3. Release workflow changes must be validated by a patch release dry-run tag.

Recommended check commands:

- `gh run list --branch <pr-branch> --limit 3`
- `gh run view <run-id> --json status,conclusion,jobs`

## Failed Patch Tag Retention Policy

Do **not** delete failed patch tags created during release hardening (`v0.2.1` to `v0.2.5` in this cycle).

Reason:

- They are part of the auditable release history and show deterministic remediation steps.
- Retention preserves evidence continuity for compliance and incident review.
