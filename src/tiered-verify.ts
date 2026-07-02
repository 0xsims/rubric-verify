// tiered-verify.ts
//
// C5: spec-conformant verification of a tiered attestation. Pure function —
// caller resolves the records (Redis stub via lookupStub, tier1 bundle from
// the store); this module takes them as arguments and verifies from CONTENT:
//
//   1. RE-DERIVE leaf: canonicalize(stub.leafMessage) -> SHA-256(0x00||canon)
//      — never trusts stored leafHash; recomputes and cross-checks it.
//   2. Walk merkleProof/Directions to batchRoot (domain-separated nodes).
//   3. Bind stub <-> bundle: batchRoot, batchSize, flushId, issuedAt, region
//      must agree with the signed envelope's fields.
//   4. Verify ML-DSA-65 signature over canonicalize(envelope) bytes.
//   5. Optional HCS cross-check: on-chain hash vs SHA-256(canonical envelope).
//
// Every failure returns verified:false with a precise reason — honest failure
// over false green. External/absent data is reported, never assumed verified.

import { createHash } from "crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { canonicalize } from "./canonical.js";
import { leafHash, verifyProof, type SpecProofStep } from "./spec-merkle.js";

export interface TieredVerifyResult {
  verified: boolean;
  reason?: string;
  checks: {
    leafRederived?: boolean;      // canonical -> leaf matches stub.leafHash
    payloadHashMatch?: boolean;   // SHA-256(canonical) matches stub.payloadHash
    proofWalk?: boolean;          // leaf -> batchRoot via merkleProof
    bundleBinding?: boolean;      // stub fields agree with signed envelope
    sigValid?: boolean;           // ML-DSA-65 over canonical envelope
    hcsMatch?: boolean;           // optional on-chain cross-check
  };
  batchRoot?: string;
  envelopeHash?: string;
}

function fail(checks: TieredVerifyResult["checks"], reason: string): TieredVerifyResult {
  return { verified: false, reason, checks };
}

export function verifyTieredAttestation(
  stub: any,
  tier1Bundle: any,
  hcsRecord?: { payload_hash?: string },
): TieredVerifyResult {
  const checks: TieredVerifyResult["checks"] = {};

  // ---- presence ----
  if (!stub || typeof stub !== "object") return fail(checks, "stub missing or invalid");
  if (!tier1Bundle || typeof tier1Bundle !== "object") return fail(checks, "tier1 bundle missing or invalid");
  if (!stub.leafMessage || typeof stub.leafMessage !== "object") {
    return fail(checks, "stub lacks leafMessage — pre-C5 stub cannot be content-verified");
  }
  if (!Array.isArray(stub.merkleProof) || !Array.isArray(stub.merkleProofDirections)
      || stub.merkleProof.length !== stub.merkleProofDirections.length) {
    return fail(checks, "stub merkle proof malformed");
  }
  const envelope = tier1Bundle.envelope;
  if (!envelope || typeof envelope !== "object") {
    return fail(checks, "tier1 bundle lacks signed envelope");
  }

  // ---- 1. re-derive leaf from content ----
  let canonical: string;
  let leaf: Buffer;
  try {
    const r = leafHash(stub.leafMessage);
    leaf = r.hash;
    canonical = r.canonical;
  } catch (e: any) {
    return fail(checks, `leaf canonicalization failed: ${e?.message ?? String(e)}`);
  }
  checks.leafRederived = leaf.toString("hex") === stub.leafHash;
  if (!checks.leafRederived) {
    return fail(checks, "re-derived leaf does not match stub.leafHash — leaf message altered");
  }
  checks.payloadHashMatch =
    createHash("sha256").update(canonical).digest("hex") === stub.payloadHash;
  if (!checks.payloadHashMatch) {
    return fail(checks, "payload_hash mismatch — canonical message altered");
  }

  // ---- 2. proof walk to batch root ----
  const proof: SpecProofStep[] = stub.merkleProof.map((h: string, i: number) => ({
    hash: h,
    dir: stub.merkleProofDirections[i],
  }));
  checks.proofWalk = verifyProof(leaf, proof, stub.batchRoot);
  if (!checks.proofWalk) {
    return fail(checks, "merkle proof does not reach batch_root — inclusion not proven");
  }

  // ---- 3. stub <-> signed envelope binding ----
  checks.bundleBinding =
    envelope.batch_root === stub.batchRoot &&
    envelope.batch_root === tier1Bundle.batch_root &&
    envelope.batch_size === stub.batchSize &&
    envelope.flush_id === stub.tier1FlushId &&
    envelope.issued_at === stub.issuedAt &&
    envelope.issuer_node_region === stub.issuerNodeRegion;
  if (!checks.bundleBinding) {
    return fail(checks, "stub fields do not bind to signed envelope (root/size/flush/time/region mismatch)");
  }

  // ---- 4. envelope signature ----
  let envCanonical: string;
  try { envCanonical = canonicalize(envelope); }
  catch (e: any) { return fail(checks, `envelope canonicalization failed: ${e?.message ?? String(e)}`); }
  try {
    const sig = new Uint8Array(Buffer.from(tier1Bundle.signature, "hex"));
    const pk = new Uint8Array(Buffer.from(tier1Bundle.publicKey, "base64"));
    checks.sigValid = ml_dsa65.verify(pk, new TextEncoder().encode(envCanonical), sig);
  } catch (e: any) {
    return fail(checks, `signature verification errored: ${e?.message ?? String(e)}`);
  }
  if (!checks.sigValid) {
    return fail(checks, "ML-DSA-65 envelope signature invalid");
  }

  // ---- 5. optional HCS cross-check ----
  const envelopeHash = createHash("sha256").update(envCanonical).digest("hex");
  if (hcsRecord?.payload_hash) {
    checks.hcsMatch = hcsRecord.payload_hash === envelopeHash;
    if (!checks.hcsMatch) {
      return fail(checks, "on-chain payload_hash does not match canonical envelope — off-chain record diverges from anchor");
    }
  }

  return { verified: true, checks, batchRoot: stub.batchRoot, envelopeHash };
}
