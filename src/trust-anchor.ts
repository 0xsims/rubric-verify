/**
 * Trust anchor validation per Rubric Verify Spec v1.0.0 §8 and §9.2.
 *
 * The trust anchor is the root of trust: a hash-pinned, founder-signed bundle
 * of federation parameters. A verifier MUST validate the trust anchor's
 * Ed25519 signature BEFORE relying on any other field within it.
 */

import { canonicalize } from './canonical.js';
import { ed25519Verify, base64Decode, hexDecode } from './crypto.js';
import { VerificationInputError } from './errors.js';
import type { TrustAnchor } from './types.js';

/**
 * Validate the trust anchor's Ed25519 signature (spec §8.2 / §9.2).
 *
 * The signature is computed over the canonical-form serialization of the
 * trust anchor with the `trust_anchor_signature` field omitted from the input.
 *
 * @returns true iff the signature verifies against `founder_key_public`.
 */
export function validateTrustAnchorSignature(ta: TrustAnchor): boolean {
  // Build the canonical input: the trust anchor with `trust_anchor_signature` removed.
  // Use object spread + delete to avoid mutating the input.
  const { trust_anchor_signature, ...rest } = ta;
  if (!trust_anchor_signature) {
    return false;
  }
  const canonical = canonicalize(rest);
  const messageBytes = new TextEncoder().encode(canonical);

  let founderKey: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    founderKey = base64Decode(ta.founder_key_public);
    signatureBytes = hexDecode(trust_anchor_signature);
  } catch {
    return false;
  }

  return ed25519Verify(founderKey, messageBytes, signatureBytes);
}

/**
 * Determine whether `issuedAt` (RFC 3339) falls within the trust anchor's
 * `[valid_from, valid_until]` window.
 *
 * `valid_until === null` means "still current" — any `issuedAt` ≥ `valid_from` matches.
 *
 * Returns false if either timestamp is malformed.
 */
export function trustAnchorCoversTime(ta: TrustAnchor, issuedAt: string): boolean {
  const issued = Date.parse(issuedAt);
  const from = Date.parse(ta.valid_from);
  if (Number.isNaN(issued) || Number.isNaN(from)) return false;
  if (issued < from) return false;
  if (ta.valid_until === null) return true;
  const until = Date.parse(ta.valid_until);
  if (Number.isNaN(until)) return false;
  return issued <= until;
}

/**
 * Select the trust anchor whose validity window contains `issuedAt`.
 *
 * Per spec §8.3, if multiple trust anchors overlap (a transition period),
 * the verifier SHOULD prefer the one whose `valid_from` is later but ≤ `issuedAt`.
 *
 * @returns the chosen anchor, or `null` if no anchor matches.
 */
export function selectTrustAnchor(
  anchors: TrustAnchor[],
  issuedAt: string,
): TrustAnchor | null {
  const issued = Date.parse(issuedAt);
  if (Number.isNaN(issued)) return null;

  const candidates = anchors.filter((ta) => trustAnchorCoversTime(ta, issuedAt));
  if (candidates.length === 0) return null;
  if (candidates.length === 1) return candidates[0] as TrustAnchor;

  // Pick the anchor with the latest valid_from (still ≤ issuedAt).
  let best = candidates[0] as TrustAnchor;
  let bestFrom = Date.parse(best.valid_from);
  for (let i = 1; i < candidates.length; i++) {
    const c = candidates[i] as TrustAnchor;
    const from = Date.parse(c.valid_from);
    if (from > bestFrom) {
      best = c;
      bestFrom = from;
    }
  }
  return best;
}

/**
 * Light structural validation — ensures required fields are present and have
 * the expected types. Does NOT validate the signature; use
 * `validateTrustAnchorSignature` for that.
 *
 * Throws `VerificationInputError` on structural defect.
 */
export function assertWellFormedTrustAnchor(ta: unknown): asserts ta is TrustAnchor {
  if (!ta || typeof ta !== 'object') {
    throw new VerificationInputError('trust anchor must be an object');
  }
  const obj = ta as Record<string, unknown>;
  const requiredStrings = [
    'spec_version',
    'protocol',
    'network',
    'valid_from',
    'founder_key_public',
    'trust_anchor_signature',
  ];
  for (const k of requiredStrings) {
    if (typeof obj[k] !== 'string') {
      throw new VerificationInputError(`trust anchor: required string field "${k}" missing/invalid`);
    }
  }
  if (typeof obj['trust_anchor_version'] !== 'number') {
    throw new VerificationInputError('trust anchor: trust_anchor_version must be a number');
  }
  if (obj['valid_until'] !== null && typeof obj['valid_until'] !== 'string') {
    throw new VerificationInputError('trust anchor: valid_until must be string or null');
  }
  if (!obj['hedera'] || typeof obj['hedera'] !== 'object') {
    throw new VerificationInputError('trust anchor: hedera section missing');
  }
  if (!obj['base'] || typeof obj['base'] !== 'object') {
    throw new VerificationInputError('trust anchor: base section missing');
  }
  if (!obj['federation'] || typeof obj['federation'] !== 'object') {
    throw new VerificationInputError('trust anchor: federation section missing');
  }
  const fed = obj['federation'] as Record<string, unknown>;
  if (
    !fed['per_node_public_keys'] ||
    typeof fed['per_node_public_keys'] !== 'object' ||
    typeof fed['threshold_public_key'] !== 'string'
  ) {
    throw new VerificationInputError('trust anchor: federation block malformed');
  }
}
