/**
 * Direct attestation verification per spec §9.3.
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
import type {
  AnchorAccess,
  DirectAttestation,
  TrustAnchor,
  VerifyDetails,
  VerifyResult,
} from './types.js';

export async function verifyDirect(
  a: DirectAttestation,
  ta: TrustAnchor,
  access: Required<AnchorAccess>,
): Promise<VerifyResult> {
  const failures: string[] = [];
  const details: VerifyDetails = {};

  /* §9.3.1 — Verify signature. */
  const messageBytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
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
    return finalize(a.attestation_id, false, details, failures);
  }

  details.signature_valid = mlDsa65Verify(publicKey, messageBytes, signature);
  if (!details.signature_valid) {
    failures.push('ML-DSA-65 signature verification failed');
  }

  /* §9.3.2 — Verify publicKey is in trust anchor. */
  const expectedKey = ta.federation.per_node_public_keys[a.issuer_node_region];
  details.public_key_matches_trust_anchor = expectedKey === a.publicKey;
  if (!details.public_key_matches_trust_anchor) {
    failures.push(
      `publicKey does not match trust anchor for region "${a.issuer_node_region}"`,
    );
  }

  /* §9.3.3 — Verify HCS anchor. */
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

  /* §9.3.4 — Verify Base anchor. */
  const base = await fetchBaseAnchor({
    baseRpc: access.baseRpc,
    contractAddress: ta.base.anchor_contract,
    txHash: a.anchors.base.tx_hash,
    fetchImpl: access.fetch,
    timeoutMs: access.timeoutMs,
  });
  details.base_anchor_confirmed =
    base !== null && hexEqual(base.aggregate_root, expectedHashHex);
  if (!details.base_anchor_confirmed) {
    failures.push('Base anchor not found or root mismatch');
  }

  /* §9.3.5 / §10.4 — Cross-chain consistency. If both anchors returned data,
     their reported hashes MUST agree with each other, regardless of whether
     each individually matches the expected hash. */
  if (hcs !== null && base !== null) {
    details.anchor_roots_match = hexEqual(hcs.payload_hash, base.aggregate_root);
  }
  if (details.anchor_roots_match === false) {
    failures.push('HCS and Base anchor disagree on payload hash');
  }

  /* §9.3.6 — Compute verdict. */
  const anchorOk = computeAnchorOk(details, access.allowSingleAnchor);
  const verified =
    !!details.signature_valid &&
    !!details.public_key_matches_trust_anchor &&
    anchorOk;

  return finalize(a.attestation_id, verified, details, failures);
}

/**
 * Anchor outcome per spec §9.3.6 + §10.3 + §10.4:
 *   - At least one anchor confirms.
 *   - If both anchors returned data, their reported hashes must agree.
 *   - If `allowSingleAnchor` is false, both MUST confirm.
 */
export function computeAnchorOk(d: VerifyDetails, allowSingleAnchor: boolean): boolean {
  const hcs = !!d.hcs_anchor_confirmed;
  const base = !!d.base_anchor_confirmed;
  if (!hcs && !base) return false;
  if (!allowSingleAnchor && !(hcs && base)) return false;
  // §10.4: if both anchors returned data and disagree, fatal regardless of confirmation.
  if (d.anchor_roots_match === false) return false;
  return true;
}

function finalize(
  attestationId: string,
  verified: boolean,
  details: VerifyDetails,
  failures: string[],
): VerifyResult {
  return { verified, attestation_id: attestationId, details, failures };
}
