# @rubric-protocol/verify

Independent, offline-capable verification of **Rubric Protocol** attestations —
including **Session Attestations** (provable records of agent behavior) — against
the public Hedera ledger. No API key, no trust in Rubric's servers.

**2.x is the chain-conformant line.** Its Merkle construction is proven
byte-for-byte against the deployed production sealer and pinned by normative
vectors that run as a ship-gate; if verifier and chain ever drift, the build
fails. (The 1.x line implemented an earlier spec reading that does not
reproduce mainnet anchors — see *1.x notice* below.)

## Install

```bash
npm install @rubric-protocol/verify
```

Node ≥ 18.

## Verify a session proof (the two-minute version)

Every sealed session exposes public, keyless endpoints:

```
GET /v1/session/:ses/manifest
GET /v1/session/:ses/proof/:seq
GET /v1/session/:ses/statement.html   (self-verifying, human-readable)
```

```ts
import { verifySessionProof, verifySessionSignature, verifyAnchorPayload } from "@rubric-protocol/verify";

const proof = await (await fetch(`${base}/v1/session/${ses}/proof/0`)).json();
const r = verifySessionProof(proof);          // leaf -> epoch -> session_root, pure SHA3 arithmetic
console.log(r.ok, r.checks);

const manifest = await (await fetch(`${base}/v1/session/${ses}/manifest`)).json();
verifySessionSignature(manifest.session_root, manifest.signature);  // ML-DSA-65 over ROOT BYTES

// bind to the public ledger: fetch the HCS mirror message your manifest's
// hcs_ref points at, base64-decode it, and check it commits to the same root
verifyAnchorPayload(manifest.session_root, decodedMirrorMessage, ses);
```

Everything below the ledger anchor is recomputable hashing; the anchor and the
post-quantum signature bind the arithmetic to the world. The operator's honesty
is never an input.

## What's in the box

- `chain-merkle` — the canonical on-chain construction (SHA3-256, RFC-6962
  domain tags, promote-odd, forest wrap) with inclusion proofs.
- `session-verify` / `session-signature` — Session Attestation verification
  per Verify Spec v2.0 §9: proof folding, event chain-rule, seal signature,
  anchor binding.
- Direct / threshold-multisig verification (SHA-256 family) — one attestation,
  1 or M-of-N ML-DSA-65 signatures over the canonical message.
- `test/chain-conformance.standalone.ts` — the normative vectors (Appendix A
  of the spec), including a live production proof. Run it yourself:

```bash
npx tsx test/chain-conformance.standalone.ts
```

## Two families, two hashes

| | Direct / threshold | Tiered / session |
|---|---|---|
| Hash | SHA-256 | **SHA3-256** |
| Signs | canonical message bytes | Merkle **root bytes** |
| Tree | none | §4.7 construction |

A verifier MUST select the hash by family (Verify Spec v2.0 §4.1).

## Live example

The first production session attestations are sealed on HCS topic
`0.0.10800940` (mainnet). Sequence 2's message commits `payload_hash` equal to
the session root of `ses_9D4FC4A64CB540F2B5006E1A51` — fetch it from any
mirror node and check it against the vectors in the conformance suite.

## 1.x notice

`@rubric-protocol/verify` 1.0.x was built from spec-side golden vectors that
predate the chain reconciliation; its attestation path is SHA-256 and cannot
reproduce mainnet tiered/session roots. It is deprecated. Its source is
retained in `src/legacy-1x/` with notes. Full disclosure: spec
`VERIFY-SPEC-v2.0-CHANGES.md`, Appendix B.3.

## Spec

`VERIFY-SPEC-v2.0-CHANGES.md` in this repo: two-family §4.1, the exact §4.7
construction, Session Attestation §9, normative vectors, disclosures.

## License

Apache-2.0 (see LICENSE).
