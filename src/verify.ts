/** Standalone signature verification for a single Rubric attestation.
 *  Mirrors the server's cryptoVerify (spec §6.3 canonical message, §5.1
 *  hex signature, base64 publicKey) — but the embedded publicKey is NEVER
 *  trusted directly: it must match the trust anchor's key for the record's
 *  issuer region. Tiered attestations are refused honestly (Phase 6). */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { createHash } from "crypto";
import { canonicalize } from "./canonical.js";
import type { TrustAnchor } from "./trust.js";

export interface VerifyResult {
  verified: boolean;
  reason: string;
  keyMatchesAnchor?: boolean;
}

export function verifyRecord(record: any, anchor: TrustAnchor): VerifyResult {
  if (!record || typeof record !== "object") return { verified: false, reason: "no record" };
  const type = record.attestation_type;
  if (type === "tiered") return { verified: false, reason: "tiered attestation verification not yet supported offline (Phase 6)" };
  if (!record.attestation_id || !record.signature || !record.publicKey) {
    return { verified: false, reason: "record missing attestation_id, signature, or publicKey" };
  }

  // Key must match the anchored federation key for this region.
  const region = String(record.issuer_node_region ?? "").toLowerCase();
  const expected = anchor.federation.per_node_public_keys[region];
  if (!expected) return { verified: false, reason: `no anchored key for region "${region}"`, keyMatchesAnchor: false };
  if (expected !== record.publicKey) {
    return { verified: false, reason: `embedded publicKey does not match the anchored key for region "${region}"`, keyMatchesAnchor: false };
  }

  let msg: string;
  try {
    msg = canonicalize({
      rubric_version: record.rubric_version,
      attestation_type: record.attestation_type,
      attestation_id: record.attestation_id,
      issuer_node_region: record.issuer_node_region,
      issued_at: record.issued_at,
      payload: record.payload,
      ...(record.provenance ? { provenance: record.provenance } : {}),
      ...(record.evidence ? { evidence: record.evidence } : {}),
      ...(record.model_ref ? { model_ref: record.model_ref } : {}),
    });
  } catch (e: any) { return { verified: false, reason: `canonicalization failed: ${e?.message}` }; }

  try {
    const pk = new Uint8Array(Buffer.from(record.publicKey, "base64"));
    const sig = new Uint8Array(Buffer.from(record.signature, "hex"));
    const ok = ml_dsa65.verify(pk, new TextEncoder().encode(msg), sig);
    if (!ok) return { verified: false, reason: "ML-DSA-65 signature invalid", keyMatchesAnchor: true };
  } catch (e: any) { return { verified: false, reason: `signature check error: ${e?.message}`, keyMatchesAnchor: true }; }

  // payload_hash consistency (binds provenance parent references)
  if (record.payload_hash) {
    const ph = createHash("sha256").update(msg).digest("hex");
    if (ph !== record.payload_hash) {
      return { verified: false, reason: "payload_hash does not match canonical message", keyMatchesAnchor: true };
    }
  }
  return { verified: true, reason: "ML-DSA-65 signature valid; key matches trust anchor", keyMatchesAnchor: true };
}
