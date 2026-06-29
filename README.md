# @rubric-protocol/verify

> **Preview release (1.0.0-rc.2).** This is an early preview published under the `next` dist-tag, not the production `1.0.0`. It verifies **real** Rubric attestations: ML-DSA-65 signature, oracle-key match against a founder-signed trust anchor, and HCS anchor confirmation against the public Hedera mainnet mirror node. Current preview limitations, by design: the trust anchor is a **staging** anchor (single oracle key; per-node key independence and the irreversible mainnet trust-anchor genesis ceremony are pending), and **Base anchoring is disabled pre-revenue** (HCS-only confirmation; single-anchor mode). The production `1.0.0` will ship after the mainnet genesis ceremony with full dual-anchor confirmation. The verification *algorithm* below is complete and final; only the trust-anchor maturity differs.

Reference TypeScript implementation of the **Rubric Attestation Verification Specification v1.0.0**.

This package lets any third party independently verify a Rubric Protocol
attestation against the public Hedera Consensus Service (HCS) and Base mainnet
ledgers, without trusting Rubric Protocol's continued operations or any
non-public infrastructure.

The verification algorithm is fully specified in
`rubric-verify-spec-v1.0.0`. This package is a conforming implementation; the
specification — not this code — is the source of truth. Any implementation
that conforms to the specification produces verification verdicts identical to
this one when given identical inputs.

> **Status:** `1.0.0-rc.1`. The verify spec is in public review prior to
> ratification as v1.0.0. The §13 / §14 federation-issued test vectors are
> populated at ratification time.

---

## Install

```bash
npm install @rubric-protocol/verify
```

Requires Node ≥ 18 (uses built-in `fetch`).

---

## Quick start

```ts
import { verify } from '@rubric-protocol/verify';

const attestation = /* fetched from your Rubric customer artifact */;
const trustAnchor = /* the published Rubric trust anchor for mainnet */;

const result = await verify({
  attestation,
  trustAnchor,
});

if (result.verified) {
  console.log(`✓ attestation ${result.attestation_id} verified`);
} else {
  console.error(`✗ verification failed:`, result.failures);
  console.error('details:', result.details);
}
```

The verifier defaults to the public Hedera mirror node and Base RPC URLs
embedded in the trust anchor. To override, pass `access`:

```ts
const result = await verify({
  attestation,
  trustAnchor,
  access: {
    hederaMirror: 'https://mainnet-public.mirrornode.hedera.com',
    baseRpc: 'https://mainnet.base.org',
    allowSingleAnchor: true, // accept verdict if only one anchor confirms (spec §10.3)
    timeoutMs: 15_000,
  },
});
```

---

## API

### `verify(options): Promise<VerifyResult>`

Top-level verification entry per spec §9.1.

```ts
interface VerifyOptions {
  attestation: Attestation;
  trustAnchor: TrustAnchor | TrustAnchor[]; // single anchor or history
  access?: AnchorAccess;
}

interface VerifyResult {
  verified: boolean;
  attestation_id: string;
  details: VerifyDetails;     // diagnostic, non-normative
  failures: string[];         // empty iff verified === true
}
```

`trustAnchor` accepts a single anchor or an array (spec §8.3 trust anchor
history). When given an array, the verifier picks the anchor whose
`[valid_from, valid_until]` window covers `attestation.issued_at`, preferring
the latest `valid_from` ≤ issuance on overlap.

Throws `VerificationInputError` only when the input cannot be coerced to a
verdict (missing required field, structurally invalid). Cryptographic failures,
anchor mismatches, and stale trust anchors all produce `verified: false` —
**never** an exception.

### Lower-level utilities

```ts
import {
  validateTrustAnchorSignature,  // Ed25519 signature check on the trust anchor itself (§8.2)
  selectTrustAnchor,             // pick an anchor from history by issuance time (§8.3)
  canonicalize,                  // RFC 8785 JCS, with spec §6.1 clarifications
  canonicalizeBytes,             // same, returning UTF-8 bytes
  verifyMerkleProof,             // raw inclusion proof check (§7.4)
  merkleLeaf,                    // SHA-256(canonical_message) (§7.1)
  merkleInternal,                // SHA-256(0x01 || L || R) (§7.2)
} from '@rubric-protocol/verify';
```

All public types are re-exported from the entry point.

---

## What this package does (and doesn't) trust

Per spec §3, the verification depends only on:

1. The attestation record.
2. The trust anchor (validated by Ed25519 signature against the embedded
   founder public key BEFORE any other field is consulted).
3. The public Hedera mirror node REST API.
4. The public Base mainnet JSON-RPC.

It does NOT depend on Rubric Protocol's continued operation. If the federation
is offline, attestations remain verifiable via any Hedera mirror node and any
Base RPC.

The trust model accommodates compromise of any single federation node's
per-node key (direct attestations from that node become invalid; tiered and
threshold attestations remain valid). It does NOT accommodate simultaneous
compromise of both anchor ledgers, compromise of the federation's threshold
key, or a verifier accepting a tampered trust anchor.

---

## Open spec issues

> **These are unresolved in the spec draft.** Implementations may produce
> different verdicts on the same input until these are settled.

### 1. Merkle hash function discrepancy (BLOCKING for tiered attestations)

The verify spec v1.0.0 draft §4.1 / §7.1 / §7.2 specifies **SHA-256** for
Merkle leaves and internal nodes, with internal-node prefix `0x01`. ADR 0005
(`Poseidon2 depth-20 Merkle tree`) specifies **Poseidon2** with no
domain separator by level.

These are mutually exclusive. **This implementation follows the verify
spec** because the spec is the conformance target for third-party verifiers.
If the federation actually emits Poseidon2-rooted tiered attestations, this
verifier will return `verified: false` for every real tiered attestation.
Either §4.1 / §7 of the spec or ADR 0005 must be amended before publication.

This is flagged in `src/merkle.ts` and is a hard pre-ratification gate.

### 2. AnchorStored event ABI not pinned

Spec §10.2 mandates "decode the `AnchorStored` event log to extract
`aggregateRoot`" but does not pin the Solidity event signature. This package
defaults to `AnchorStored(bytes32)` with `aggregateRoot` as a non-indexed
parameter (i.e. in the log's `data` field), with a fallback decode for the
indexed-parameter layout (`topics[1]`). If the deployed Base contract uses a
different signature, the event-decode logic in `src/anchors/base.ts` must be
adjusted, or the `eventSignature` option (currently internal) must be exposed
in the public API.

### 3. ML-DSA-65 signature size: spec says 3293, FIPS 204 final says 3309

The verify spec §4.2 states "Signatures are 3293 bytes in length." That number is from the FIPS 204 *draft*. FIPS 204 *final* (NIST, August 2024) defines ML-DSA-65 signatures as **3309 bytes** — the difference is a 16-byte structural change in the signature encoding. `@noble/post-quantum` (and any other conforming ML-DSA-65 library) produces 3309-byte signatures, which is what the federation actually emits.

This implementation uses 3309 (`ML_DSA_65_SIGNATURE_BYTES = 3309` in `src/crypto.ts`) to match runtime reality. The verify spec §4.2 should be updated — either to state 3309, or to cite FIPS 204 by reference and omit the byte-count assertion.

The §14.8 truncated-signature test still works under either size: any signature significantly shorter than 3309 (or 3293) is rejected by the length pre-check before invoking the verify primitive.

### 4. §13 / §14 test vectors are placeholders

The spec's normative test vectors are populated at ratification time with
real federation-issued data. The test suite in `test/verify.test.ts` exercises
the verification logic against locally-generated keys and signatures (covering
all §14 invalid-vector classes), but does not yet pin against the canonical
v1.0.0 vectors.

---

## Cryptographic primitives

| Use | Algorithm | Library |
|---|---|---|
| Hash (canonical message, Merkle leaf, Merkle internal) | SHA-256 | `@noble/hashes` |
| Attestation signing (direct, tiered, threshold) | ML-DSA-65 (FIPS 204) | `@noble/post-quantum` |
| Trust anchor signing | Ed25519 | `@noble/curves` |
| Ethereum event topic selector | Keccak-256 | `@noble/hashes` |

ML-DSA-65 public keys are 1952 bytes, signatures are 3309 bytes (FIPS 204 final; see Open Spec Issues §3). Threshold
signatures use the same primitive — the aggregated form is structurally
identical to a non-aggregated signature (spec §4.3) and verifies against the
threshold-aggregated public key.

The implementation uses single-source-of-truth `@noble/*` libraries throughout,
matching the federation's runtime choice (M30, see audit doc).

---

## Build

```bash
npm install
npm run typecheck
npm test
npm run build
```

Produces ESM (`dist/esm/`), CommonJS (`dist/cjs/`), and TypeScript declarations
(`dist/types/`).

---

## Testing

```bash
npm test                # all tests
npm run test:coverage   # with coverage report
```

Test coverage:

- `test/canonical.test.ts` — RFC 8785 conformance, the spec §6.2 reference
  example (`{"a":1,"b":2}` from `{ b: 2, a: 1 }`, 13 UTF-8 bytes).
- `test/merkle.test.ts` — synthetic 4-leaf and 3-leaf (odd, right-padded)
  trees; internal/leaf prefix verification; rejection of tampered siblings
  (spec §14.6).
- `test/verify.test.ts` — end-to-end with locally generated ML-DSA-65 +
  Ed25519 keys and a stubbed `fetch`. Covers valid direct/tiered/threshold,
  all five regions (§13.5), §14.1 tampered signature, §14.2 tampered payload,
  §14.3 wrong key, §14.5 anchor disagreement, §14.6 tampered Merkle proof,
  §14.7 wrong threshold_keylist_hash, §14.8 truncated signature, single-anchor
  acceptance (§10.3), both-anchors-fail rejection, `allowSingleAnchor=false`
  enforcement, expired trust-anchor windows.

---

## Conformance statement

This implementation conforms to the verification algorithm specified in
**Rubric Attestation Verification Specification v1.0.0** (draft, dated
2026-05-07), subject to the open spec issues above. When the spec is ratified
and §13 / §14 vectors are populated, conformance will be re-verified against
those canonical vectors and recorded in `CHANGELOG.md`.

A specific implementation conforms to the spec if and only if it:

1. Returns `verified = true` for every attestation in the §13 valid-vector set.
2. Returns `verified = false` for every attestation in the §14 invalid-vector
   set.

Both under the same trust anchor, with access to the public Hedera and Base
mainnets.

---

## Contributing

Bug reports and conformance issues: file at the repo's issue tracker.
Pull requests welcome for spec-conformance improvements and additional test
vectors. The verification algorithm itself is fixed by the spec; implementation
changes that diverge from the spec will not be accepted.

---

## License

Apache-2.0.

Copyright 2026 Echelon Intelligence Group LLC.
