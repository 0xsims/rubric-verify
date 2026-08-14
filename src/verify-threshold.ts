/**
 * Threshold attestation verification per spec §9.5.
 *
 * Identical to direct verification with two modifications:
 *   1. Public key check uses TA.federation.threshold_public_key (not per-node).
 *   2. Validate A.threshold_keylist_hash matches TA.federation.keylist_aggregate_hash.
 *
 * The aggregated signature is structurally identical to a non-aggregated
 * ML-DSA-65 signature (spec §4.3); the verifier does not reconstruct from
 * individual contributions.
 */

import { canonicalizeBytes } from './canonical.js';
import {
  base64Decode,
  hexDecode,
  hexEncode,
  hexEqual,
  mlDsa65Verify,
  sha256,
} from './crypto.js';
import { fetchHcsMessage } from './anchors/hcs.js';
import { fetchBaseAnchor } from './anchors/base.js';
import { computeAnchorOk, checkConsensusSuiteWindow } from './verify-direct.js';
import type {
  AnchorAccess,
  ThresholdAttestation,
  TrustAnchor,
  VerifyDetails,
  VerifyResult,
} from './types.js';

export async function verifyThreshold(
  a: ThresholdAttestation,
  ta: TrustAnchor,
  access: Required<AnchorAccess>,
): Promise<VerifyResult> {
  const failures: string[] = [];
  const details: VerifyDetails = {};

  /* Signature over canonical message of common fields (same as direct §9.3.1). */
  const messageBytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
    ...(a.provenance ? { provenance: a.provenance } : {}),
    ...(a.evidence ? { evidence: a.evidence } : {}),
  });
  const expectedHashHex = hexEncode(sha256(messageBytes));

  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = base64Decode(a.publicKey);
    signature = hexDecode(a.signature);
  } catch (e) {
    failures.push(`malformed key/signature encoding: ${(e as Error).message}`);
    details.signature_valid = false;
    return { verified: false, attestation_id: a.attestation_id, details, failures };
  }
  details.signature_valid = mlDsa65Verify(publicKey, messageBytes, signature);
  if (!details.signature_valid) {
    failures.push('ML-DSA-65 (threshold) signature verification failed');
  }

  /* Public key must equal the threshold-aggregated key from the trust anchor. */
  details.public_key_matches_trust_anchor =
    a.publicKey === ta.federation.threshold_public_key;
  if (!details.public_key_matches_trust_anchor) {
    failures.push('publicKey does not match trust anchor threshold key');
  }

  /* threshold_keylist_hash must match. */
  details.threshold_keylist_hash_matches = hexEqual(
    a.threshold_keylist_hash,
    ta.federation.keylist_aggregate_hash,
  );
  if (!details.threshold_keylist_hash_matches) {
    failures.push('threshold_keylist_hash does not match trust anchor');
  }

  /* Anchor checks — identical structure to direct (single payload hash). */
  const hcs = await fetchHcsMessage({
    hederaMirror: access.hederaMirror,
    topicId: a.anchors.hcs.topic_id,
    txId: a.anchors.hcs.tx_id,
    expected: {
      attestation_id: a.attestation_id,
      attestation_type: a.attestation_type,
      issuer_node_region: a.issuer_node_region,
      issued_at: a.issued_at,
    },
    fetchImpl: access.fetch,
    timeoutMs: access.timeoutMs,
  });
  details.hcs_anchor_confirmed =
    hcs !== null && hexEqual(hcs.payload_hash, expectedHashHex);
  if (!details.hcs_anchor_confirmed) {
    failures.push('HCS anchor not found or payload hash mismatch');
  }

  /* Layer 2 — suite downgrade defense (consensus-time cross-check). */
  const l2 = checkConsensusSuiteWindow(ta, hcs, details);
  if (l2) failures.push(l2);

  /* Base anchoring is not always active. An attestation that was never
     anchored carries an empty tx_hash, and "not anchored" is a different fact
     from "anchored to a different root". Collapsing them reported a mismatch
     on every attestation, which teaches readers to ignore the one message
     that should stop them. Mirrors the INDETERMINATE handling used for the
     HCS aggregate-inclusion check above. */
  let base: Awaited<ReturnType<typeof fetchBaseAnchor>> | null = null;
  const baseTx = a.anchors.base?.tx_hash;
  if (!baseTx) {
    Reflect.deleteProperty(details, 'base_anchor_confirmed');
  } else {
    base = await fetchBaseAnchor({
      baseRpc: access.baseRpc,
      contractAddress: ta.base.anchor_contract,
      txHash: baseTx,
      fetchImpl: access.fetch,
      timeoutMs: access.timeoutMs,
    });
    if (base === null) {
      Reflect.deleteProperty(details, 'base_anchor_confirmed');
      failures.push('Base anchor INDETERMINATE: tx_hash present but anchor not retrievable');
    } else {
      details.base_anchor_confirmed = hexEqual(base.aggregate_root, expectedHashHex);
      if (!details.base_anchor_confirmed) {
        failures.push('Base anchor root mismatch');
      }
    }
  }

  if (hcs !== null && base !== null) {
    details.anchor_roots_match = hexEqual(hcs.payload_hash, base.aggregate_root);
  }
  if (details.anchor_roots_match === false) {
    failures.push('HCS and Base anchor disagree on payload hash');
  }

  const verified =
    !!details.signature_valid &&
    !!details.public_key_matches_trust_anchor &&
    !!details.threshold_keylist_hash_matches &&
    computeAnchorOk(details, access.allowSingleAnchor) &&
    !l2;

  return { verified, attestation_id: a.attestation_id, details, failures };
}
