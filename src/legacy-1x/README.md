# legacy-1x — source of the npm 1.x line (quarantined)

These five modules are the published `@rubric-protocol/verify` 1.0.x source,
grafted here when the two repo histories were reconciled (see the v2.0 merge
commit). They implement the rc2-era spec reading — SHA-256 Merkle leaves over
the §6.3 message, "ratified" golden vectors of 2026-06-11 — which the August
2026 chain reconciliation proved does NOT reproduce production anchors (the
chain seals SHA3-256 typed-leaf forests; see src/chain-merkle.ts and Verify
Spec v2.0 §4.1/§4.7).

Status: excluded from the build. Retained for history and for porting the
parts that are genuinely good — notably trust.ts (ledger-rooted trust-anchor
bootstrapping, whose commitment check correctly uses SHA3-256) and the
fetch/walk CLI ergonomics. Port deliberately; do not re-enable wholesale.
