/**
 * Merkle proof tests.
 *
 * Constructs a small balanced tree per spec §7 (SHA-256, internal-node prefix
 * 0x01, no leaf prefix), generates an inclusion proof, and verifies it.
 */

import { sha256, hexEncode, concatBytes3 } from '../src/crypto.js';
import { merkleInternal, merkleLeaf, verifyMerkleProof } from '../src/merkle.js';
import type { MerkleDirection } from '../src/types.js';

/** Compute the depth-d Merkle root from leaf hashes by right-padding with the last leaf. */
function computeRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error('empty leaves');
  let level = leaves.slice();
  while (level.length > 1) {
    if (level.length % 2 !== 0) {
      level.push(level[level.length - 1] as Uint8Array); // duplicate last
    }
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(merkleInternal(level[i] as Uint8Array, level[i + 1] as Uint8Array));
    }
    level = next;
  }
  return level[0] as Uint8Array;
}

/** Generate the inclusion proof for `index` in a tree built from `leaves`. */
function buildProof(
  leaves: Uint8Array[],
  index: number,
): { proof: string[]; directions: MerkleDirection[] } {
  const proof: string[] = [];
  const directions: MerkleDirection[] = [];
  let level = leaves.slice();
  let idx = index;
  while (level.length > 1) {
    if (level.length % 2 !== 0) {
      level.push(level[level.length - 1] as Uint8Array);
    }
    const sibIdx = idx ^ 1; // flip last bit
    const sibling = level[sibIdx] as Uint8Array;
    proof.push(hexEncode(sibling));
    // If sibling index is to the right of `idx`, sibling is on the right (direction "R").
    directions.push(sibIdx > idx ? 'R' : 'L');
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(merkleInternal(level[i] as Uint8Array, level[i + 1] as Uint8Array));
    }
    level = next;
    idx = idx >>> 1;
  }
  return { proof, directions };
}

describe('Merkle (spec §7)', () => {
  it('leaf uses the 0x00 domain separator (RFC 6962, spec §7.1)', () => {
    const msg = new TextEncoder().encode('hello');
    // Fixed vectors, computed independently of this implementation:
    //   sha256('hello')         = 2cf24dba...  <- what a leaf must NOT be
    //   sha256(0x00 || 'hello') = 8a2a5c9b...  <- what it must be
    // Untagged leaves share a hash space with internal nodes, which is the
    // second-preimage weakness RFC 6962 tagging exists to prevent.
    expect(hexEncode(merkleLeaf(msg))).toBe(
      '8a2a5c9b768827de5a9552c38a044c66959c68f6d2f21b5260af54d2f87db827',
    );
    expect(hexEncode(merkleLeaf(msg))).not.toBe(hexEncode(sha256(msg)));
  });

  it('internal node uses 0x01 prefix (spec §7.2)', () => {
    const a = new Uint8Array(32).fill(0xaa);
    const b = new Uint8Array(32).fill(0xbb);
    const expected = sha256(concatBytes3(new Uint8Array([0x01]), a, b));
    expect(hexEncode(merkleInternal(a, b))).toBe(hexEncode(expected));
  });

  it('verifies inclusion for a 4-leaf balanced tree', () => {
    const leaves = ['L0', 'L1', 'L2', 'L3'].map((s) => merkleLeaf(new TextEncoder().encode(s)));
    const root = computeRoot(leaves);
    const rootHex = hexEncode(root);
    for (let i = 0; i < leaves.length; i++) {
      const { proof, directions } = buildProof(leaves, i);
      const result = verifyMerkleProof(leaves[i] as Uint8Array, proof, directions, rootHex);
      expect(result.valid).toBe(true);
      expect(result.computedRoot).toBe(rootHex);
    }
  });

  it('verifies inclusion for an odd-leaf tree (right-padding by duplication)', () => {
    const leaves = ['L0', 'L1', 'L2'].map((s) => merkleLeaf(new TextEncoder().encode(s)));
    const root = computeRoot(leaves);
    const rootHex = hexEncode(root);
    for (let i = 0; i < leaves.length; i++) {
      const { proof, directions } = buildProof(leaves, i);
      const result = verifyMerkleProof(leaves[i] as Uint8Array, proof, directions, rootHex);
      expect(result.valid).toBe(true);
    }
  });

  it('rejects a tampered sibling (spec §14.6 invalid vector)', () => {
    const leaves = ['L0', 'L1', 'L2', 'L3'].map((s) => merkleLeaf(new TextEncoder().encode(s)));
    const root = computeRoot(leaves);
    const { proof, directions } = buildProof(leaves, 0);
    const corrupted = proof.slice();
    // Flip the last hex character.
    const _orig = corrupted[0] as string;
    corrupted[0] = (_orig[0] === '0' ? 'f' : '0') + _orig.slice(1);
    const result = verifyMerkleProof(
      leaves[0] as Uint8Array,
      corrupted,
      directions,
      hexEncode(root),
    );
    expect(result.valid).toBe(false);
  });

  it('throws on direction/proof length mismatch', () => {
    const leaves = ['L0', 'L1'].map((s) => merkleLeaf(new TextEncoder().encode(s)));
    const root = computeRoot(leaves);
    expect(() =>
      verifyMerkleProof(leaves[0] as Uint8Array, ['00'], [], hexEncode(root)),
    ).toThrow();
  });

  it('throws on invalid direction value', () => {
    const leaves = ['L0', 'L1'].map((s) => merkleLeaf(new TextEncoder().encode(s)));
    const root = computeRoot(leaves);
    const { proof } = buildProof(leaves, 0);
    expect(() =>
      verifyMerkleProof(
        leaves[0] as Uint8Array,
        proof,
        ['X' as MerkleDirection],
        hexEncode(root),
      ),
    ).toThrow();
  });
});
