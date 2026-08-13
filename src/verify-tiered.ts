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
import { resolveLeafMessage } from './leaf-source.js';
import { canonicalize } from './canonical.js';
import { chainLeafDigest, buildChainTree, chainForestWrap } from './chain-merkle.js';
import { fetchHcsAggregate } from './anchors/hcs-aggregate.js';
import { computeAnchorOk, checkConsensusSuiteWindow } from './verify-direct.js';
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
  // The producer adds optional siblings conditionally; carry through whatever
  // this record has. A fixed key list here silently breaks every record that
  // carries a key the list omits — see buildAttestationMessage.
  const leafSource = resolveLeafMessage(a);
  if (leafSource.error) {
    failures.push(leafSource.error);
  }
  const leafBytes = merkleLeaf(canonicalizeBytes(leafSource.message));

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

  /* §9.4.2 — Verify the signed batch ENVELOPE.
   *
   * The producer signs canonicalize(envelope) over seven keys, not the raw
   * batch_root bytes (tiered-aggregator.ts: signCanonical(batchEnvelope)).
   * Verifying over hexDecode(batch_root) checks bytes nobody ever signed. */
  const env = a.tier1?.envelope;
  if (!env) {
    details.signature_valid = false;
    failures.push(
      'record does not carry its signed tier-1 envelope (tier1.envelope), ' +
      'so the batch signature cannot be checked',
    );
  } else {
    // Bind the envelope to this record before trusting it — otherwise a valid
    // signature over some OTHER batch would pass. Mirrors the bundleBinding
    // check in the server's tiered-verify.
    const bound =
      env.batch_root === a.batch_root &&
      env.batch_size === a.batch_size &&
      env.issued_at === a.issued_at &&
      env.issuer_node_region === a.issuer_node_region;
    if (!bound) {
      details.signature_valid = false;
      failures.push('signed envelope does not bind to this record (root/size/time/region mismatch)');
    } else {
      let publicKey: Uint8Array;
      let signature: Uint8Array;
      try {
        publicKey = base64Decode(a.tier1?.publicKey ?? a.publicKey);
        signature = hexDecode(a.tier1?.signature ?? a.signature);
      } catch (e) {
        failures.push(`malformed encoding: ${(e as Error).message}`);
        details.signature_valid = false;
        return { verified: false, attestation_id: a.attestation_id, details, failures };
      }
      const envBytes = new TextEncoder().encode(canonicalize(env));
      details.signature_valid = mlDsa65Verify(publicKey, envBytes, signature);
      if (!details.signature_valid) {
        failures.push('batch envelope signature verification failed');
      }
    }
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
  /* A tiered record is not on HCS individually. What is on the topic is the
   * tier-2 aggregate envelope, reachable only by sequence number. Reconstruct:
   *   aggregate leaf = DOCUMENT_HASH{forestRoot: batch_root, itemCount}
   *   tree root      = single-leaf tree over it
   *   aggregateRoot  = self-pair wrap of that root
   * confirmed against seq 287406 before this was written. */
  const seq = a.anchors.hcs.sequence_number;
  const agg =
    typeof seq === 'number' && seq > 0
      ? await fetchHcsAggregate({
          hederaMirror: access.hederaMirror,
          topicId: a.anchors.hcs.topic_id,
          sequenceNumber: seq,
          fetchImpl: access.fetch,
          timeoutMs: access.timeoutMs,
        })
      : null;

  if (!agg) {
    details.hcs_anchor_confirmed = false;
    failures.push(
      `tier-2 aggregate anchor not retrievable (topic ${a.anchors.hcs.topic_id} ` +
      `sequence ${String(seq)})`,
    );
  } else if (agg.tier1Count === 1) {
    const leafDigest = chainLeafDigest('DOCUMENT_HASH', {
      forestRoot: a.batch_root,
      itemCount: a.batch_size,
    });
    const treeRoot = buildChainTree([leafDigest]).root;
    const reconstructed = chainForestWrap(treeRoot);
    details.hcs_anchor_confirmed = reconstructed === agg.aggregateRoot;
    if (!details.hcs_anchor_confirmed) {
      failures.push(
        `batch_root does not reconstruct to the anchored aggregateRoot ` +
        `(computed ${reconstructed.slice(0, 16)}…, anchored ${agg.aggregateRoot.slice(0, 16)}…)`,
      );
    }
  } else {
    // The aggregate tree held more than one tier-1 flush. Its sibling roots are
    // not published in this record, so the walk cannot be completed by a third
    // party. Say so rather than returning a verdict the evidence cannot carry.
    Reflect.deleteProperty(details, 'hcs_anchor_confirmed');
    failures.push(
      `aggregate inclusion INDETERMINATE: the anchor at sequence ${String(seq)} ` +
      `covers ${String(agg.tier1Count)} tier-1 flushes and this record does not ` +
      `carry the aggregate proof path, so batch_root cannot be walked to ` +
      `aggregateRoot independently`,
    );
  }

  /* Layer 2 — suite downgrade defense (consensus-time cross-check). */
  const l2 = checkConsensusSuiteWindow(ta, hcs, details);
  if (l2) failures.push(l2);

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
    computeAnchorOk(details, access.allowSingleAnchor) &&
    !l2;

  return { verified, attestation_id: a.attestation_id, details, failures };
}
