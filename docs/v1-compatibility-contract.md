# VAOL v1.0 Compatibility Contract

This contract defines compatibility guarantees for REST, gRPC/protobuf, schemas, and SDKs.

## 1. Versioning Model

1. Semantic versioning for server/SDK releases.
2. `v1.x.y` guarantees backward compatibility for:
   1. DecisionRecord v1 schema
   2. existing REST endpoints and response fields
   3. existing gRPC methods and protobuf field numbers
3. Breaking changes require `v2.0.0`.

## 2. REST Compatibility Rules

1. Existing endpoints cannot change semantics incompatibly in `v1.x`.
2. New response fields must be additive and optional for clients.
3. Existing required request fields cannot become stricter without versioned opt-in.
4. Error reason-code strings used for deterministic policy/security behavior are treated as contract.

## 3. gRPC/Protobuf Compatibility Rules

1. Never reuse or renumber protobuf fields.
2. New fields must be optional/additive.
3. Existing RPC names and request/response message shapes remain stable.
4. Reserved/deprecated fields must remain reserved permanently.

## 4. DecisionRecord Schema Rules

1. `schema_version="v1"` payload remains verifiable indefinitely.
2. New evidence data in `v1.x` must be optional.
3. Any new required field or semantic reinterpretation requires `v2` payload type.

## 5. SDK Compatibility Rules

1. Existing instrumentation wrapper APIs remain stable in `v1.x`.
2. New optional arguments may be added with sane defaults.
3. SDK verification behavior must remain deterministic across patch/minor upgrades.

## 6. Compatibility Test Gate (Release)

Every release candidate must pass:

1. full unit/e2e/tamper test matrix
2. strict profile verification tests (Ed25519 + Sigstore)
3. replay/tenant-isolation regressions
4. protobuf backwards-compat checks
5. auditor demo script

## 7. Deprecation Policy

1. Minimum deprecation window: 2 minor releases.
2. Deprecation notices must appear in:
   1. API reference
   2. release notes
   3. changelog

