/**
 * Merkle tree proof verification per Rubric Verify Spec v1.0.0 §7.
 *
 * Construction:
 *   - Hash function: SHA-256 (spec §4.1).
 *   - Leaf:     leaf_i = SHA-256(0x00 || canonical_message_i)       (§7.1)
 *   - Internal: internal(L, R) = SHA-256(0x01 || L || R)            (§7.2)
 *               where 0x00 and 0x01 are RFC 6962 domain separators that
 *               keep leaf and internal-node hashes in disjoint spaces.
 *   - Tree shape: binary, balanced, depth 20 (max 2^20 leaves);
 *                 odd levels are right-padded by duplicating the last leaf.
 *
 * NOTE — open spec discrepancy:
 *   ADR 0005 specifies Poseidon2 as the Merkle hash function. The verify spec
 *   v1.0.0 draft §4.1 / §7 specifies SHA-256. This implementation follows the
 *   verify spec because the spec is the conformance target. If real federation
 *   tiered attestations are constructed with Poseidon2, either §4.1 or ADR 0005
 *   must be amended before publication. See README §"Open Spec Issues".
 */

import { sha256, hexDecode, hexEncode, hexEqual, concatBytes3 } from './crypto.js';
import type { MerkleDirection } from './types.js';

/** Domain separator byte for leaves (RFC 6962). */
const LEAF_NODE_PREFIX = new Uint8Array([0x00]);

/** Domain separator byte for internal nodes (spec §7.2). */
const INTERNAL_NODE_PREFIX = new Uint8Array([0x01]);

const EMPTY = new Uint8Array(0);

/**
 * Compute an internal Merkle node: SHA-256(0x01 || left || right).
 */
export function merkleInternal(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes3(INTERNAL_NODE_PREFIX, left, right));
}

/**
 * Compute a leaf hash: SHA-256(0x00 || canonical_message_bytes).
 *
 * Confirmed against live records rather than the draft: for attestation
 * eb7310f4 the unprefixed digest is d2319dec..., which is that record's
 * payload_hash, while the 0x00-prefixed digest is 836939c0... -- its
 * batch_root, and the value actually anchored on HCS. The producer and
 * constructions.json both tag the leaf; verify-spec v1.0.0 §7.1 is wrong.
 */
export function merkleLeaf(canonicalMessageBytes: Uint8Array): Uint8Array {
  return sha256(concatBytes3(LEAF_NODE_PREFIX, canonicalMessageBytes, EMPTY));
}

/**
 * Verify a Merkle inclusion proof per spec §7.4.
 *
 * @param leaf - leaf hash bytes (output of `merkleLeaf`).
 * @param proof - sibling hashes as hex strings, ordered from leaf level upward.
 * @param directions - per-step sibling position. "L" = sibling on left of `current`;
 *                     "R" = sibling on right of `current`.
 * @param expectedRoot - expected root, as a hex string.
 *
 * @returns `{ valid, computedRoot }` where `computedRoot` is the hex-encoded
 * root produced by walking the proof. `valid` is true iff `computedRoot`
 * equals `expectedRoot` (case-insensitive, `0x`-tolerant).
 *
 * Throws `Error` if `proof` and `directions` have different lengths or if any
 * direction value is not "L" or "R".
 */
export function verifyMerkleProof(
  leaf: Uint8Array,
  proof: string[],
  directions: MerkleDirection[],
  expectedRoot: string,
): { valid: boolean; computedRoot: string } {
  if (proof.length !== directions.length) {
    throw new Error(
      `merkle proof/direction length mismatch: ${proof.length} vs ${directions.length}`,
    );
  }

  let current = leaf;
  for (let i = 0; i < proof.length; i++) {
    const sibling = hexDecode(proof[i] as string);
    const dir = directions[i];
    if (dir === 'L') {
      current = merkleInternal(sibling, current);
    } else if (dir === 'R') {
      current = merkleInternal(current, sibling);
    } else {
      throw new Error(`invalid merkle direction at index ${i}: ${String(dir)}`);
    }
  }

  const computedRoot = hexEncode(current);
  return {
    valid: hexEqual(computedRoot, expectedRoot),
    computedRoot,
  };
}
