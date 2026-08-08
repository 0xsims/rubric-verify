# Rubric Verify Spec — v1.0.0-rc3 changes

**Status:** draft for `~/rubric-verify` (supersedes rc2 where stated)
**Basis:** every construction and vector below is reproduced against deployed
production code by the conformance harness (`reference/conformance/`), which runs
in the tempus deploy-gate on every commit. Nothing here is asserted from a draft.
**Live examples:** HCS topic `0.0.10800940` (memo `rubric-rsa-session-close-v1`,
mainnet), sequences 1–2, are real sealed sessions produced by this construction.

## Summary of changes from rc2

1. §4.1 is corrected: rc2 described SHA-256 as the universal hash; in fact Rubric
   has **two attestation families with two fixed hashes**. (Chain is truth; the
   spec under-described it.)
2. New §4.7: the exact tiered Merkle construction (SHA3-256, RFC-6962 tags,
   promote-odd, forest self-pair wrap).
3. New §9: **Session Attestation** (`attestation_type: "session"`), the behavioral
   attestation class: hash-chained event streams sealed per-session, ML-DSA-65
   signed, HCS-anchored, publicly verifiable.
4. Appendix A: canonical test vectors (normative).
5. Appendix B: disclosures (RUBRIC-SEC-2026-001; ADR-0005 supersession).

---

## §4.1 (REPLACES rc2 §4.1) — Hash functions

Rubric attestations use two families, each with a fixed hash:

(a) **Direct / threshold-multisig** attestations use **SHA-256** and sign the
canonical message bytes directly (ML-DSA hashes internally). The `message_hash`
record field is `hex(SHA-256(JCS(message)))` and serves as index/precheck only.

(b) **Tiered / batched** attestations — including Session Attestation (§9) —
use **SHA3-256** and sign a Merkle root built by the construction in §4.7.

Implementations MUST select the hash by family. A verifier MUST reject a tiered
anchor whose recomputed root under SHA3-256/§4.7 does not match. *(SHA-256 as a
universal hash, as stated in rc2, holds only for the direct/threshold family.)*

Canonicalization for both families is RFC 8785 JCS; all hashing is over
`canonicalize(value)` UTF-8 bytes.

## §4.7 (NEW) — Tiered Merkle construction (normative)

```
algorithm : SHA3-256

# leaf preimage (type-bound)
leaf_pre  : "sha3-256:" + SHA3-256( JCS({ __leafType: TYPE, ...data }) )

# inner tree
leaf      : SHA3-256( 0x00 || bytes(hex after the "sha3-256:" prefix) )   # RFC-6962 leaf tag
node      : SHA3-256( 0x01 || L || R )                                    # RFC-6962 node tag
odd level : PROMOTE the lone node (no duplication)

# outer wrap (single-tree forest)
root      : SHA3-256( utf8( tree_root_hex || tree_root_hex ) )            # untagged self-pair
```

Wire forms (both families): digests/roots are bare lowercase hex (the `algo:`
prefix exists only inside `leaf_pre`); signatures are bare lowercase hex
(ML-DSA-65 = 3309 bytes = 6618 hex chars); public keys are standard-padded
base64 of raw key bytes (URL-safe base64 MUST be rejected). The signed preimage
for tiered roots is the **decoded root bytes** (`hexDecode(root)`), never the
hex string.

`TYPE` ∈ `{DOCUMENT_HASH, DATA_RECORD, AGENT_OUTPUT, HUMAN_REVIEW,
MODEL_VERSION, IMPACT_ASSESSMENT, THIRD_PARTY_MODEL, SESSION_EVENT}`.
(`SESSION_EVENT` is added in rc3 for §9.)

---

## §9 (NEW) — Session Attestation

### 9.1 Purpose and guarantees

A session attests **behavior over time**: an ordered, gap-free record of events
produced by a named actor between an open and a close. A sealed session proves,
to any verifier with no trust in the operator:

- **Inclusion** — event `seq` occurred with exactly these bytes;
- **Order** — events occurred in the committed sequence (hash chain, §9.2);
- **Completeness** — the session contains exactly `leaf_count` events and no
  others (per-epoch `itemCount` is committed at the session tier, §9.3);
- **Time bound** — the root existed no later than the anchor's public consensus
  timestamp (§9.5).

Sessions MAY run payload-blind (`body_mode: "digest"`): events carry
`body_digest` only, committing to content without disclosing it.

### 9.2 Event leaves and the hash chain

Each event is a JSON record with at minimum:

```
{ "v": 1, "ses": <session id>, "seq": <0-based integer>,
  "ts": <ISO-8601>, "kind": <string>,
  "actor": { "agent_id": <string>, "key_fp": <hex64> },
  "body": <JSON or null>, "body_digest": <hex64 or null>,
  "prev": <hex64 or null> }
```

Chain rule: `prev` MUST be `null` for `seq 0` and otherwise
`SHA3-256(JCS(previous event record))` (the *content digest* of the full prior
record). Writers MUST reject an append whose `seq` is not the next index or
whose `prev` does not match; re-sends of an existing `seq` MUST be byte-identical
(idempotent) or rejected. This makes insertion, deletion, and reordering
detectable at write time and provable after sealing.

Leaf digest for the tree: `SHA3-256(JCS({ __leafType: "SESSION_EVENT", ...event }))`
per §4.7.

### 9.3 Epochs and the session root

Events are sealed in contiguous **epochs** (operator-chosen boundaries; the
proof format makes verification independent of epoch size):

```
epoch_root   = forestWrap( buildTree( events[i..j] as SESSION_EVENT leaves ) )
epoch leaf   = makeLeaf("DOCUMENT_HASH", { forestRoot: epoch_root, itemCount: j-i+1 })
session_root = forestWrap( buildTree( epoch leaves, in epoch order ) )
```

`itemCount` inside each epoch leaf is what makes completeness provable: the
signed, anchored `session_root` commits to the exact event count of every epoch.

### 9.4 Sealing states and signature

A closed session is in exactly one state, and verifiers MUST treat them as
strictly ordered assurance levels:

- `unsigned-p1` — closed, root computed, no signature (fail-closed floor);
- `signed-unanchored` — root signed, anchor pending;
- `sealed` — a real ledger consensus receipt exists for the root. `sealed`
  MUST NOT be claimed on submission alone.

Signature object (in the manifest):

```
{ "alg": "ml-dsa-65", "sig": <6618 hex chars>,
  "public_key_b64": <standard-padded base64, raw 1952 bytes>,
  "key_fp": <hex64 = SHA3-256(raw public key bytes)> }
```

The signed preimage is the decoded `session_root` bytes (§4.7).

### 9.5 Anchor message (HCS)

One message per sealed session, on a dedicated topic. Schema (observed live at
topic `0.0.10800940` seq 2):

```
{ "v": 1, "kind": "rsa-session-close", "ses": <session id>,
  "payload_hash": <session_root, hex64>,
  "manifest_attestation_id": <att_...>,
  "core_digest": <hex64> }
```

Verifiers MUST check `payload_hash == session_root` byte-for-byte against the
public mirror record and take the consensus timestamp from the ledger, not from
the operator.

### 9.6 Public read API

Verifiability is the product: implementations MUST serve these without
authentication (GET/HEAD):

```
GET /v1/session/:ses/manifest          -> manifest (see 9.7)
GET /v1/session/:ses/proof/:seq        -> composed two-tier proof (see 9.7)
GET /v1/session/:ses/statement         -> statement JSON bundle
GET /v1/session/:ses/statement.html    -> self-contained, self-verifying HTML
```

Writes (open/append/checkpoint/close) remain authenticated and are out of scope
for this spec beyond the chain rules in §9.2.

### 9.7 Proof object and verification procedure

The manifest MUST include at least: `ses`, `leaf_count`, `session_root`,
`sealing_status`, and (when past `unsigned-p1`/`signed-unanchored`) the
signature object of §9.4 and an `hcs_ref { topic_id, sequence_number }`.

A proof for event `seq` MUST include: the full `leaf`, `leaf_digest`,
`leaf_path` (ordered `{position: "left"|"right", hash}` siblings),
`epoch_root`, `epoch_leaf_count`, `epoch_index`, `epoch_path`, `session_root`.

Verification (all recomputable with any SHA3-256 implementation):

1. `SHA3-256(JCS({__leafType:"SESSION_EVENT", ...leaf})) == leaf_digest`
2. `forestWrap( fold(leaf_digest, leaf_path) ) == epoch_root`
   where `fold` starts at the tagged leaf `SHA3(0x00||bytes)` and combines
   `SHA3(0x01||L||R)` per the path positions.
3. `epoch_leaf = SHA3-256(JCS({__leafType:"DOCUMENT_HASH",
   forestRoot: epoch_root, itemCount: epoch_leaf_count}))`;
   `forestWrap( fold(epoch_leaf, epoch_path) ) == session_root`
4. `session_root ==` manifest `session_root` `==` anchor `payload_hash` on the
   public mirror; verify the ML-DSA-65 signature over the root bytes against
   `public_key_b64`, and `key_fp == SHA3-256(raw key)`.

Steps 1–3 are pure arithmetic; step 4 binds the arithmetic to a public ledger
and a key. No step takes the operator's word for anything.

---

## Appendix A — canonical test vectors (normative)

Conforming implementations MUST reproduce all of the following. (Pinned against
the deployed production builder 2026-08-07; enforced in CI by the conformance
gate.)

**A.1 Tiered inner roots** — leaves `{a:1}..{a:n}` as `AGENT_OUTPUT`:

```
n=1  d84ecda9fe4388e9e7dd94f9aef78d5763d5269268f30f0f527970be56204cb8
n=2  f14c93e239c7372eb7357edfdbac03053ea018cc000043f26decd62d86636e29
n=3  b17df03177e3b101bd8165c9b4b8af714ad4266f708833e5274bd355aecc83a0
n=5  68739317569906c998868377d452c59755a6b97850a985d5ee9726ebd704d706
```

**A.2 Tiered session composition** — epochs `[{seq:0},{seq:1},{seq:2}]` and
`[{seq:3},{seq:4}]` as `AGENT_OUTPUT`, wrapped, then composed per §9.3:

```
session_root  4de3a2da7694f6ba931cded3f31b4a4dbc2dbc5f59738fd0955704e06cbf2a52
```

**A.3 SESSION_EVENT inner roots** — leaves `{a:1}..{a:n}` as `SESSION_EVENT`:

```
n=1  b965e02e0acb0d7c26deec78d369e0d769f07ab38c543e1dccd4fb2884e5cb4a
n=2  9165bbd3e10bde6ef547f657b4db75e031a4e79224e7ec3854605c93e1681955
n=3  809c50b06aabf99968319c43f41f77bacb0bf8fa354eb57861e21971b65c7aa7
n=5  a6c29d27a6c93e25c53358c3e7fbdf84966a648f2f83f1f335318cf974e6c420
```

**A.4 SESSION_EVENT session composition** — epochs `[{seq:0},{seq:1},{seq:2}]`
and `[{seq:3},{seq:4}]` as `SESSION_EVENT`, wrapped, composed per §9.3:

```
session_root  7a09d2733bd8f6a62090730b9d4ca018ed038c29c105f1ac9fe282d05c9e108e
```

**A.5 Direct-family probe** — `hex(SHA-256(JCS({family:"direct",
msg:"rubric-conformance-probe", n:1})))`:

```
63ae2efcc629818de7a338d1d98dbd41d7abfa08aa76436a99a0e200ba862f2b
```

**A.6 Live production reference** — session
`ses_9D4FC4A64CB540F2B5006E1A51`, `session_root
f4f06e0a2349c70c1ef7d5e56c48f575f1b23836daa461432eefc5c4a24e222f`, anchored as
sequence 2 on topic `0.0.10800940`; independently verifiable via any Hedera
mirror node.

## Appendix B — disclosures

**B.1 RUBRIC-SEC-2026-001 (bounded, historical).** `buildTreeV2` leaf tagging
hex-decoded a string carrying a `sha3-256:` prefix; the decode yields an empty
buffer, so v2-era leaves tagged to `H(0x00)` and **v2 aggregate roots commit to
leaf count and order-of-commitment, not per-leaf content**. 322 historical v2
anchors were sealed this way and are retained verbatim (immutability forbids
re-sealing; they still reproduce their recorded roots). All anchors from v3
onward bind content. The boundary is the bundle's `treeVersion` field; verifiers
select v2/v3 accordingly.

**B.2 ADR-0005 (Poseidon2) — Superseded.** Poseidon2 was aspirational and never
deployed; no anchor is sealed with it. Any future ZK path requires a new ADR
scoped to that subsystem, explicitly not the attestation Merkle hash.
