# Changelog

## 2.2.0

### Added

- **Aggregate inclusion is verifiable for multi-flush anchors.** Records now
  publish `anchors.hcs.aggregate_flushes`; the verifier rebuilds the tier-2
  tree, locates its own leaf by `batch_root`, derives the inclusion path and
  folds it to the anchored `aggregateRoot`. Any record whose anchor covered
  more than one tier-1 flush previously reported INDETERMINATE -- 1422 stored
  records were in that state. The list is checked against the anchored
  tier1Count, and this record against its own batch_root and batch_size, so a
  substituted list cannot make a false record pass.
- New export: `checkAggregateInclusion`.

## 2.1.0

### Fixed

- **Merkle leaves are now tagged with the RFC 6962 `0x00` byte.** `merkleLeaf`
  computed `SHA-256(message)`; the producer, `constructions.json`, and every
  anchored record use `SHA-256(0x00 || message)`. Verify-spec v1.0.0 s7.1 said
  otherwise and was wrong. Untagged leaves also shared a hash space with
  internal nodes -- the second-preimage weakness the tagging exists to prevent.
  Every tiered attestation previously failed verification.
- **Optional leaf keys are no longer dropped.** `provenance`, `evidence`,
  `model_ref`, `compliance_ref` and `client_attestation` are hashed into the
  leaf when present. `/v1/verify/:id` exposes them only inside
  `attestation.stub`, so `resolveLeafMessage` reads them from
  `stub.leafMessage` -- but only after confirming all six always-present keys
  are byte-identical to the record, and rejecting any key outside the
  published leaf shape.
- **Batch signatures verify over the signed envelope.** ML-DSA-65 was checked
  against `hexDecode(batch_root)`, bytes nobody ever signs. It now verifies
  `canonicalize(tier1.envelope)` with binding checks on root, size, time and
  region.
- **HCS anchors resolve by sequence number.** A tiered record is not on the
  topic individually; the tier-2 aggregate envelope is. Aggregates covering
  more than one flush report INDETERMINATE rather than a verdict the published
  evidence cannot support.
- **Default API is the apex**, which fans out to peer regions, instead of
  `us.` which returned 404 for records served elsewhere.

### Added

- `resolveLeafMessage` (`src/leaf-source.ts`)
- `fetchHcsAggregate` (`src/anchors/hcs-aggregate.ts`)

Verified against live anchored records: `eb7310f4` (client-signed, seven-key
leaf) and `5c974ee7` (unsigned, six-key leaf) both verify. 75/75 tests pass.

## 2.0.0-rc.1 — chain reconciliation (unreleased)

**Breaking / corrective.** The 1.x line implements the rc2-era SHA-256 Merkle
construction ratified from spec-side vectors (2026-06-11); the August 2026
chain reconciliation proved production anchors are sealed with SHA3-256
typed-leaf forests. 1.x therefore cannot reproduce mainnet tiered/session
roots and is deprecated.

- NEW `src/chain-merkle.ts` — the canonical on-chain construction (SHA3-256,
  RFC-6962 tags, promote-odd, forest self-pair wrap), proven against the
  deployed sealer and pinned by normative vectors.
- NEW `src/session-verify.ts` + `src/session-signature.ts` — Session
  Attestation verification (Verify Spec v2.0 §9): 4-check proof verification,
  event chain-rule, ML-DSA-65 seal signature over root bytes, HCS anchor
  payload binding. Verified against a live production session (topic
  0.0.10800940 seq 2).
- NEW `test/chain-conformance.standalone.ts` — normative vectors A.1-A.6;
  ship-gate: if it fails, the verifier drifted from the chain.
- Histories reconciled: the published 1.x source is retained under
  `src/legacy-1x/` (excluded from build) for porting its good parts
  (trust bootstrap, CLI ergonomics).
- Spec: `VERIFY-SPEC-v2.0-CHANGES.md` (retitled from rc3) — two-family
  §4.1 correction, §4.7 construction, §9 Session Attestation, disclosures
  incl. the 1.x mismatch (B.3).


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
