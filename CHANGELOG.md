# Changelog

All notable changes to `@rubric/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc.1] — 2026-05-09

Initial public release candidate. Reference TypeScript implementation of the
Rubric Attestation Verification Specification v1.0.0 (draft).

### Added

- Top-level `verify(options)` entry per spec §9.1.
- Direct attestation verification per spec §9.3.
- Tiered attestation verification per spec §9.4.
- Threshold attestation verification per spec §9.5.
- RFC 8785 JSON Canonicalization Scheme (JCS) implementation per spec §6.1,
  with the spec §6.2 reference example as a regression test.
- Merkle inclusion proof verification per spec §7.4 (SHA-256, internal-node
  prefix `0x01`, leaf prefix none).
- Trust anchor Ed25519 signature validation per spec §8.2 / §9.2.
- Trust anchor history support per spec §8.3 (single anchor or array).
- Hedera mirror node anchor fetch per spec §10.1.
- Base mainnet RPC anchor fetch per spec §10.2 (default
  `AnchorStored(bytes32)` with non-indexed and indexed-parameter fallback).
- Single-anchor acceptance per spec §10.3 (`allowSingleAnchor` option,
  default `true`).
- Anchor-disagreement rejection per spec §10.4.
- Truncated-signature short-circuit per spec §14.8 (length pre-check before
  invoking ML-DSA-65 verify primitive).
- Test coverage for §13.5 (all five regions) and the entire §14 invalid-vector
  set (§14.1 through §14.8) using locally generated keys.
- Dual ESM + CommonJS build with TypeScript declarations.

### Known issues / open spec questions

- **Merkle hash function discrepancy.** Verify spec §4.1 / §7.1 / §7.2
  specify SHA-256; ADR 0005 specifies Poseidon2. This implementation follows
  the spec. Real federation-issued tiered attestations will not verify
  successfully until either the spec or ADR 0005 is amended. See README §
  "Open Spec Issues."
- **ML-DSA-65 signature size: 3293 vs 3309.** Verify spec §4.2 states 3293
  bytes (FIPS 204 draft). FIPS 204 final defines 3309 bytes, which is what
  `@noble/post-quantum` produces and what the federation emits. This
  implementation uses 3309 (`src/crypto.ts`); spec §4.2 should be updated.
- **§13 / §14 test vectors are placeholders.** Will be pinned at spec
  ratification.
- **AnchorStored event ABI not normatively pinned.** Default decoder assumes
  `AnchorStored(bytes32)`.

### Cryptographic dependencies

- `@noble/hashes` ^1.5.0 (SHA-256, Keccak-256)
- `@noble/curves` ^1.6.0 (Ed25519)
- `@noble/post-quantum` ^0.2.1 (ML-DSA-65)

[1.0.0-rc.1]: https://github.com/rubric-protocol/rubric-verify/releases/tag/v1.0.0-rc.1
