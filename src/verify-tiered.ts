/**
 * Tiered attestation verification per spec §9.4.
 *
 * Differences from direct:
 *   - The signed message is the batch_root (not the individual canonical message).
 *   - The verifier first reconstructs the Merkle root from the leaf + proof.
 *   - The HCS/Base anchors are expected to record `batch_root`, not the
 *     individual leaf hash.
 */

import { canonicalizeBytes } from './canonical.js';
import {
  base64Decode,
  hexDecode,
  hexEqual,
  mlDsa65Verify,
} from './crypto.js';
import { fetchHcsMessage } from './anchors/hcs.js';
import { fetchBaseAnchor } from './anchors/base.js';
import { merkleLeaf, verifyMerkleProof } from './merkle.js';
import { computeAnchorOk } from './verify-direct.js';
import type {
  AnchorAccess,
  TieredAttestation,
  TrustAnchor,
  VerifyDetails,
  VerifyResult,
} from './types.js';

export async function verifyTiered(
  a: TieredAttestation,
  ta: TrustAnchor,
  access: Required<AnchorAccess>,
): Promise<VerifyResult> {
  const failures: string[] = [];
  const details: VerifyDetails = {};

  /* §9.4.1 — Reconstruct Merkle root. */
  const leafBytes = merkleLeaf(
    canonicalizeBytes({
      rubric_version: a.rubric_version,
      attestation_type: a.attestation_type,
      attestation_id: a.attestation_id,
      issuer_node_region: a.issuer_node_region,
      issued_at: a.issued_at,
      payload: a.payload,
    }),
  );

  let merkleResult: ReturnType<typeof verifyMerkleProof>;
  try {
    merkleResult = verifyMerkleProof(
      leafBytes,
      a.merkle_proof,
      a.merkle_proof_directions,
      a.batch_root,
    );
  } catch (e) {
    failures.push(`Merkle proof malformed: ${(e as Error).message}`);
    details.merkle_proof_valid = false;
    return { verified: false, attestation_id: a.attestation_id, details, failures };
  }
  details.merkle_proof_valid = merkleResult.valid;
  if (!merkleResult.valid) {
    failures.push('Merkle proof does not reconstruct to batch_root');
  }

  /* §9.4.2 — Verify batch_root signature. */
  let publicKey: Uint8Array;
  let signature: Uint8Array;
  let batchRootBytes: Uint8Array;
  try {
    publicKey = base64Decode(a.publicKey);
    signature = hexDecode(a.signature);
    batchRootBytes = hexDecode(a.batch_root);
  } catch (e) {
    failures.push(`malformed encoding: ${(e as Error).message}`);
    details.signature_valid = false;
    return { verified: false, attestation_id: a.attestation_id, details, failures };
  }
  details.signature_valid = mlDsa65Verify(publicKey, batchRootBytes, signature);
  if (!details.signature_valid) {
    failures.push('Batch root signature verification failed');
  }

  /* §9.4.3 — Verify publicKey is in trust anchor. */
  const expectedKey = ta.federation.per_node_public_keys[a.issuer_node_region];
  details.public_key_matches_trust_anchor = expectedKey === a.publicKey;
  if (!details.public_key_matches_trust_anchor) {
    failures.push('publicKey does not match trust anchor');
  }

  /* §9.4.4 — Verify anchors against batch_root. */
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
    hcs !== null && hexEqual(hcs.payload_hash, a.batch_root);
  if (!details.hcs_anchor_confirmed) {
    failures.push('HCS anchor mismatch with batch_root');
  }

  const base = await fetchBaseAnchor({
    baseRpc: access.baseRpc,
    contractAddress: ta.base.anchor_contract,
    txHash: a.anchors.base.tx_hash,
    fetchImpl: access.fetch,
    timeoutMs: access.timeoutMs,
  });
  details.base_anchor_confirmed =
    base !== null && hexEqual(base.aggregate_root, a.batch_root);
  if (!details.base_anchor_confirmed) {
    failures.push('Base anchor mismatch with batch_root');
  }

  if (hcs !== null && base !== null) {
    details.anchor_roots_match = hexEqual(hcs.payload_hash, base.aggregate_root);
  }
  if (details.anchor_roots_match === false) {
    failures.push('HCS and Base anchor disagree on batch_root');
  }

  /* Compute verdict. */
  const verified =
    !!details.merkle_proof_valid &&
    !!details.signature_valid &&
    !!details.public_key_matches_trust_anchor &&
    computeAnchorOk(details, access.allowSingleAnchor);

  return { verified, attestation_id: a.attestation_id, details, failures };
}
