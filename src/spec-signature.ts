/**
 * Specification self-signing and verification (spec §6.4).
 *
 * This module implements the convention by which the Rubric Verify specification
 * document is itself founder-signed, and by which any party reproducibly verifies
 * that signature. It is the document analogue of `validateTrustAnchorSignature`
 * for trust anchors: two derived fields in §15 (the document SHA-256 and the founder
 * signature) are excluded from the signable bytes by replacing their values with the
 * sentinel `UNSIGNED`; everything else in the document is bound.
 */
import { sha256, hexEncode, hexDecode, base64Decode } from './crypto.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';

/** The sentinel that occupies each derived field's value in the signable form (§6.4.1). */
export const SPEC_SIG_SENTINEL = 'UNSIGNED';

/** Exact field labels in §15. The verifier substitutes the value after each, to end-of-line. */
const SHA_LABEL = 'Specification SHA-256 (this document, v1.0.0): ';
const SIG_LABEL = 'Founder signature (ML-DSA-65 [FIPS 204], hex): ';

/**
 * Replace the value following `label` (up to end-of-line) with `SPEC_SIG_SENTINEL`.
 * Throws if the label does not appear exactly once — the convention requires a single,
 * unambiguous occurrence of each derived field.
 */
function substituteFieldValue(doc: string, label: string): string {
  const idx = doc.indexOf(label);
  if (idx === -1) {
    throw new Error(`spec-signature: label not found: ${JSON.stringify(label)}`);
  }
  if (doc.indexOf(label, idx + label.length) !== -1) {
    throw new Error(`spec-signature: label appears more than once: ${JSON.stringify(label)}`);
  }
  const valueStart = idx + label.length;
  let lineEnd = doc.indexOf('\n', valueStart);
  if (lineEnd === -1) lineEnd = doc.length;
  return doc.slice(0, valueStart) + SPEC_SIG_SENTINEL + doc.slice(lineEnd);
}

/**
 * Build the signable form `B` of the specification (§6.4.1): the full document with the
 * SHA-256 and Founder-signature field VALUES replaced by the sentinel. Deterministic:
 * signer and verifier derive identical bytes.
 */
export function buildSignableForm(documentText: string): Uint8Array {
  let d = substituteFieldValue(documentText, SHA_LABEL);
  d = substituteFieldValue(d, SIG_LABEL);
  return new TextEncoder().encode(d);
}

/** Read the value following `label` (to end-of-line) from a signed document. */
function readFieldValue(doc: string, label: string): string {
  const idx = doc.indexOf(label);
  if (idx === -1) throw new Error(`spec-signature: label not found: ${JSON.stringify(label)}`);
  const valueStart = idx + label.length;
  let lineEnd = doc.indexOf('\n', valueStart);
  if (lineEnd === -1) lineEnd = doc.length;
  return doc.slice(valueStart, lineEnd).trim();
}

export interface SpecVerifyResult {
  ok: boolean;
  hashMatches: boolean;
  signatureValid: boolean;
  reason?: string;
}

/**
 * Verify the specification signature (§6.4.3).
 *
 * @param documentText  the specification document as received (with real hash + signature in §15)
 * @param founderPublicKeyB64  the founder ML-DSA-65 public key (base64), obtained out-of-band
 *                             (pinned in @rubric/verify); MUST equal §15's recorded Founder public key
 */
export function verifySpecSignature(
  documentText: string,
  founderPublicKeyB64: string,
): SpecVerifyResult {
  // 1. Reconstruct the signable form B.
  const B = buildSignableForm(documentText);

  // 2. Recompute SHA-256(B) and compare to the recorded value.
  const recordedHash = readFieldValue(documentText, SHA_LABEL);
  const computedHash = hexEncode(sha256(B));
  const hashMatches = recordedHash.toLowerCase() === computedHash.toLowerCase();
  if (!hashMatches) {
    return { ok: false, hashMatches: false, signatureValid: false,
      reason: 'document SHA-256 does not match recorded value (document modified)' };
  }

  // 3. Verify the founder signature over B with the provided founder public key.
  const recordedSigHex = readFieldValue(documentText, SIG_LABEL);
  if (recordedSigHex === SPEC_SIG_SENTINEL) {
    return { ok: false, hashMatches, signatureValid: false, reason: 'specification is unsigned' };
  }
  let signatureValid = false;
  try {
    const sig = hexDecode(recordedSigHex);
    const pk = base64Decode(founderPublicKeyB64);
    signatureValid = ml_dsa65.verify(pk, B, sig);
  } catch (e) {
    return { ok: false, hashMatches, signatureValid: false,
      reason: `signature decode/verify error: ${(e as Error).message}` };
  }
  if (signatureValid) {
    return { ok: true, hashMatches, signatureValid: true };
  }
  return {
    ok: false,
    hashMatches,
    signatureValid: false,
    reason: 'founder signature does not verify against B with the given key',
  };
}
