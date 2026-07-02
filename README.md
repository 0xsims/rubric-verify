# @rubric-protocol/verify

Offline verifier for [Rubric Protocol](https://rubric-protocol.com) attestations.
Verifies ML-DSA-65 (NIST FIPS 204) signatures, decision-provenance chains, and
Hedera ledger anchors **independently — no Rubric infrastructure in the trust path.**

```
git clone https://github.com/0xsims/rubric-verify
cd rubric-verify && npm install && npm run build
node dist/cli.js 187db855-7fc7-4dff-87c7-77bd953b813d
```

Requires Node 18+. The ID above is a real 4-agent lending decision anchored on
Hedera mainnet — try it.

## Trust model

The only constants baked into this package:

| Constant | Value |
|---|---|
| Hedera topic | `0.0.10416909` |
| Operator account | `0.0.3923341` |
| Trust-anchor commitment | sequence `276123` |

Everything else derives from the ledger at run time:

1. Fetch the commitment message at seq 276123 from a public Hedera mirror node.
   Require the paying account to be the Rubric operator — only that account can
   write to the topic.
2. The commitment carries the SHA3-256 of the trust-anchor document's exact
   bytes. Fetch the document from **any** source (the committed URL, a local
   file via `--trust-doc`, an adversary's copy — the source does not matter),
   hash it, require a match.
3. Trust the federation public keys inside the hash-verified document, within
   their validity window. Every record's embedded key must **match** the
   anchored key for its issuer region — embedded keys are never trusted
   directly.

Package updates are not trust events. The root of trust is a ledger entry no
one can rewrite — including Rubric.

## What it checks

**Direct attestations:** canonical form rebuilt per spec §6.3 → ML-DSA-65
signature over the exact bytes → payload hash → provenance walk binding every
parent and evidence reference to its exact content hash → optional per-record
HCS anchor cross-check (identity and consensus timestamp taken from the mirror
node, never from the record).

**Tiered attestations** (self-contained shape): leaf message re-derived from
content → Merkle inclusion proof to the signed batch root → stub↔envelope
binding → ML-DSA-65 over the canonical envelope → anchored key match.

**External evidence** (data from outside the attested boundary) is disclosed
and fingerprinted, never vouched for. A verifier that cannot say "I don't
know" cannot be believed when it says "verified."

## Verifying hostile records

Every cross-reference is hash-bound, so the record source is untrusted by
construction. Hand the tool records from anyone:

```
node dist/cli.js <attestation-id> --dir ./records-from-opposing-counsel
```

## Forgery drills (worked examples)

**1. Tampered content** — flip one byte of an attested payload:

```
✕ 76668518 ML-DSA-65 signature invalid
NOT VERIFIED
```

**2. Forged key** — attacker signs with their own keypair:

```
✕ 76668518 embedded publicKey does not match the anchored key for region "us"
NOT VERIFIED
```

**3. Poisoned trust document** — attacker swaps a federation key:

```
✕ trust-anchor document hash mismatch:
  on-chain commitment: c7308f1a…
  fetched document:    19c4d31a…
NOT VERIFIED
```

Each rejection happens at the correct layer, with the reason named. Exit code
0 = verified, 1 = not verified, 2 = usage error — scriptable in CI or an
examination workpaper.

## What this proves — and what it does not

**Proves:** the records are byte-for-byte what Rubric's anchored keys signed;
the decision's lineage links resolve to exact content; nothing was altered,
substituted, re-ordered, or backdated after attestation; anchored records
carry consensus timestamps from a public ledger no operator controls.

**Does not prove:** that the attested events occurred as described (Rubric
signs what the integrating system submits — capture integrity is the
integrator's responsibility), or that every relevant action was attested
(an unattested step is invisible, not disproven). These limits are stated
because a proof system that overclaims is worthless in front of the people
this tool exists for.

## License

Apache-2.0 · © 2026 Echelon Intelligence Group LLC
