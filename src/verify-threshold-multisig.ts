/**
 * threshold-multisig attestation verification (spec §X.2, V1–V7).
 *
 * M-of-N independent per-node ML-DSA-65 signatures over one identical canonical
 * message. No key reconstruction. Each signer's key is checked against the trust
 * anchor's per_node_public_keys (the §9.3.2 binding check, applied per signer).
 * The quorum (incl. signer_regions) is INSIDE the signed message, so all M
 * signatures bind the quorum claim.
 */

import { canonicalizeBytes } from './canonical.js';
import { fetchHcsMessage } from './anchors/hcs.js';
import { base64Decode, hexDecode, mlDsa65Verify, sha256, hexEncode } from './crypto.js';
import type {
  AnchorAccess,
  ThresholdMultisigAttestation,
  TrustAnchor,
  VerifyDetails,
  VerifyResult,
} from './types.js';

function finalize(
  attestationId: string,
  verified: boolean,
  details: VerifyDetails,
  failures: string[],
): VerifyResult {
  return { verified, attestation_id: attestationId, details, failures };
}

export async function verifyThresholdMultisig(
  a: ThresholdMultisigAttestation,
  ta: TrustAnchor,
  _access: Required<AnchorAccess>,
): Promise<VerifyResult> {
  const failures: string[] = [];
  const details: VerifyDetails = {};
  const id = a.attestation_id ?? '';

  /* V1 — SHAPE */
  if (
    a.attestation_type !== 'threshold-multisig' ||
    !a.quorum || typeof a.quorum.m !== 'number' || typeof a.quorum.n !== 'number' ||
    !Array.isArray(a.quorum.signer_regions) ||
    !Array.isArray(a.signatures) || a.signatures.length === 0
  ) {
    failures.push('threshold-multisig shape invalid');
    return finalize(id, false, details, failures);
  }

  /* V2 — POLICY (anchor must declare threshold_policy; attestation cannot self-weaken) */
  const policy = ta.federation.threshold_policy;
  if (!policy || typeof policy.m !== 'number' || typeof policy.n !== 'number' ||
      a.quorum.m !== policy.m || a.quorum.n !== policy.n) {
    failures.push('quorum policy does not match trust anchor');
    return finalize(id, false, details, failures);
  }

  /* V3 — QUORUM SIZE */
  if (a.signatures.length !== a.quorum.m || a.quorum.signer_regions.length !== a.quorum.m) {
    failures.push('quorum size mismatch');
    return finalize(id, false, details, failures);
  }

  /* V4 — DISTINCTNESS + SET EQUALITY */
  const sigRegions = a.signatures.map((s) => s.region);
  const declRegions = a.quorum.signer_regions;
  const sigSet = new Set(sigRegions);
  const declSet = new Set(declRegions);
  if (
    sigSet.size !== sigRegions.length ||
    declSet.size !== declRegions.length ||
    sigSet.size !== declSet.size ||
    [...sigSet].some((r) => !declSet.has(r))
  ) {
    failures.push('signer set inconsistent or contains duplicates');
    return finalize(id, false, details, failures);
  }

  /* V5 — CANONICAL + payload_hash. quorum is INSIDE the signed message. */
  const messageBytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
    quorum: a.quorum,
    ...(a.provenance ? { provenance: a.provenance } : {}),
    ...(a.evidence ? { evidence: a.evidence } : {}),
  });
  const expectedHashHex = hexEncode(sha256(messageBytes));
  details.expected_payload_hash = expectedHashHex;

  // Item 3: HCS cross-check. Fetch the ledger-anchored compact envelope by tx_id and
  // confirm its payload_hash equals the recomputed canonical hash (mirrors verify-direct).
  // Fail-closed when tx_id is present; diagnostic-only when absent (pre-item-4 attestations).
  const hcsTxId = a.anchors?.hcs?.tx_id;
  const hcsTopicId = a.anchors?.hcs?.topic_id;
  if (hcsTxId && hcsTopicId) {
    const hcs = await fetchHcsMessage({
      hederaMirror: _access.hederaMirror,
      topicId: hcsTopicId,
      txId: hcsTxId,
      expected: {
        attestation_id: a.attestation_id,
        attestation_type: a.attestation_type,
        issuer_node_region: a.issuer_node_region,
        issued_at: a.issued_at,
      },
      fetchImpl: _access.fetch,
      timeoutMs: _access.timeoutMs,
    });
    details.hcs_anchor_confirmed =
      hcs !== null && hcs.payload_hash.toLowerCase() === expectedHashHex.toLowerCase();
    if (!details.hcs_anchor_confirmed) {
      failures.push('HCS anchor not found or payload hash mismatch');
      return finalize(id, false, details, failures);
    }
  } else {
    // No tx_id on the attestation — cannot perform ledger cross-check. Record diagnostic;
    // signatures + quorum + per-node binding are still fully verified below.
    details.hcs_anchor_confirmed = false;
  }

  /* V6 — PER-SIGNER binding + signature (loop the §9.3.2 check) */
  for (const s of a.signatures) {
    const region = s.region as keyof typeof ta.federation.per_node_public_keys;
    const expected = ta.federation.per_node_public_keys[region];
    if (!expected) {
      failures.push(`no trust-anchor key for region ${s.region}`);
      return finalize(id, false, details, failures);
    }
    if (s.publicKey !== expected) {
      details.public_key_matches_trust_anchor = false;
      failures.push(`publicKey does not match trust anchor for region ${s.region}`);
      return finalize(id, false, details, failures);
    }
    let ok: boolean;
    try {
      ok = mlDsa65Verify(base64Decode(s.publicKey), messageBytes, hexDecode(s.signature));
    } catch {
      ok = false;
    }
    if (!ok) {
      details.signature_valid = false;
      failures.push(`ML-DSA-65 signature invalid for region ${s.region}`);
      return finalize(id, false, details, failures);
    }
  }

  /* V7 — all passed */
  details.public_key_matches_trust_anchor = true;
  details.signature_valid = true;
  details.quorum_satisfied = true;
  return finalize(id, true, details, failures);
}
