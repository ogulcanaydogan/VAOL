# VAOL Production Profile (Helm)

This profile hardens VAOL for regulated deployments by enforcing fail-closed behavior, tenant-bound authentication, startup integrity checks, and checkpoint anchoring defaults.

## Goals

1. Enforce authenticated access (`authMode=required`).
2. Enforce policy fail-closed (`policyMode=fail-closed`).
3. Enforce startup integrity checks (`failOnStartupCheck=true`).
4. Enable deterministic checkpoint behavior (`checkpointEvery`, `checkpointInterval`, `anchorMode`).
5. Prefer Sigstore strict mode in connected environments (`sigstoreRekorRequired=true` in production profile).

## Helm Values Mapping

The chart now supports a deployment profile switch:

- `profile.mode=dev`
- `profile.mode=production`

When `profile.mode=production`, the server args are forced to:

- `--auth-mode` from `profile.production.authMode` (default `required`)
- `--policy-mode` from `profile.production.policyMode` (default `fail-closed`)
- `--anchor-mode` from `profile.production.anchorMode` (default `local`)
- `--sigstore-rekor-required` from `profile.production.sigstoreRekorRequired` (default `true`, when signer mode is `sigstore`)
- `--fail-on-startup-check` from `profile.production.failOnStartupCheck` (default `true`)

## Recommended Override File

Create `values-production.yaml`:

```yaml
profile:
  mode: production

server:
  signingMode: sigstore
  sigstoreFulcioURL: https://fulcio.sigstore.dev
  sigstoreRekorURL: https://rekor.sigstore.dev

  authMode: required
  jwtIssuer: https://issuer.example.com
  jwtAudience: vaol-api
  jwtTenantClaim: tenant_id
  jwtSubjectClaim: sub
  jwksURL: https://issuer.example.com/.well-known/jwks.json

  policyMode: fail-closed
  checkpointEvery: 100
  checkpointInterval: 5m
  anchorMode: http
  anchorURL: https://anchors.example.com/vaol/checkpoints

  rebuildOnStart: true
  failOnStartupCheck: true

opa:
  enabled: true
```

## Deploy

```bash
helm upgrade --install vaol ./deploy/helm/vaol \
  -f ./deploy/helm/vaol/values.yaml \
  -f ./deploy/helm/vaol/values-production.yaml
```

## Verification Checklist

1. `GET /v1/health` returns `status=ok`.
2. Unauthenticated record append attempts fail with `401`.
3. OPA outage causes deterministic deny (`policy_engine_unavailable`) rather than allow.
4. Checkpoint records are persisted and available via `/v1/ledger/checkpoints/latest`.
5. `vaol verify bundle --profile strict` passes for untampered bundles and fails for tampered bundles.
