import { describe, it, expect } from '@jest/globals';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { buildSignableForm, verifySpecSignature, SPEC_SIG_SENTINEL } from '../src/spec-signature.js';
import { sha256, hexEncode, base64Encode } from '../src/crypto.js';

// A minimal stand-in document with the exact §15 field labels the convention targets.
function makeDoc(shaVal: string, sigVal: string): string {
  return [
    '# Rubric Verify Spec (test fixture)',
    '',
    'Some body content that is bound by the signature.',
    'More content with unicode: \u00a78.3 trust-anchor set.',
    '',
    '## 15. Specification Hash and Signature',
    '',
    '```',
    `Specification SHA-256 (this document, v1.0.0): ${shaVal}`,
    `Founder signature (ML-DSA-65 [FIPS 204], hex): ${sigVal}`,
    'Founder public key (ML-DSA-65 [FIPS 204], base64): <pinned>',
    '```',
    '',
    'End of document.',
    '',
  ].join('\n');
}

describe('specification self-signing (spec §6.4)', () => {
  it('round-trips: sign the signable form, then verifySpecSignature returns ok', () => {
    const kp = ml_dsa65.keygen(new Uint8Array(32).fill(7));
    const pubB64 = base64Encode(kp.publicKey);

    // 1. Unsigned doc carries the sentinel in both derived fields.
    const unsigned = makeDoc(SPEC_SIG_SENTINEL, SPEC_SIG_SENTINEL);

    // 2. Build signable form B and sign per §6.4.2.
    const B = buildSignableForm(unsigned);
    const hashHex = hexEncode(sha256(B));
    const sig = ml_dsa65.sign(kp.secretKey, B);
    const sigHex = Buffer.from(sig).toString('hex');

    // 3. Write real values into the two derived fields.
    const signed = makeDoc(hashHex, sigHex);

    // 4. Verify.
    const r = verifySpecSignature(signed, pubB64);
    expect(r.hashMatches).toBe(true);
    expect(r.signatureValid).toBe(true);
    expect(r.ok).toBe(true);
  });

  it('signable form is identical before and after writing real field values (self-reference resolved)', () => {
    const kp = ml_dsa65.keygen(new Uint8Array(32).fill(7));
    const unsigned = makeDoc(SPEC_SIG_SENTINEL, SPEC_SIG_SENTINEL);
    const B1 = buildSignableForm(unsigned);
    const hashHex = hexEncode(sha256(B1));
    const sig = ml_dsa65.sign(kp.secretKey, B1);
    const signed = makeDoc(hashHex, Buffer.from(sig).toString('hex'));
    const B2 = buildSignableForm(signed);
    // The whole point: stripping the derived fields yields identical bytes either way.
    expect(Buffer.from(B2).toString('hex')).toBe(Buffer.from(B1).toString('hex'));
  });

  it('rejects a tampered body (one byte changed) — hash mismatch', () => {
    const kp = ml_dsa65.keygen(new Uint8Array(32).fill(7));
    const pubB64 = base64Encode(kp.publicKey);
    const unsigned = makeDoc(SPEC_SIG_SENTINEL, SPEC_SIG_SENTINEL);
    const B = buildSignableForm(unsigned);
    const hashHex = hexEncode(sha256(B));
    const sig = ml_dsa65.sign(kp.secretKey, B);
    const signed = makeDoc(hashHex, Buffer.from(sig).toString('hex'));

    const tampered = signed.replace('Some body content', 'Some body content!');
    const r = verifySpecSignature(tampered, pubB64);
    expect(r.hashMatches).toBe(false);
    expect(r.ok).toBe(false);
  });

  it('rejects the wrong founder public key — signature invalid', () => {
    const kp = ml_dsa65.keygen(new Uint8Array(32).fill(7));
    const wrong = ml_dsa65.keygen(new Uint8Array(32).fill(9));
    const unsigned = makeDoc(SPEC_SIG_SENTINEL, SPEC_SIG_SENTINEL);
    const B = buildSignableForm(unsigned);
    const hashHex = hexEncode(sha256(B));
    const sig = ml_dsa65.sign(kp.secretKey, B);
    const signed = makeDoc(hashHex, Buffer.from(sig).toString('hex'));

    const r = verifySpecSignature(signed, base64Encode(wrong.publicKey));
    expect(r.hashMatches).toBe(true);     // body unchanged
    expect(r.signatureValid).toBe(false); // wrong key
    expect(r.ok).toBe(false);
  });

  it('reports unsigned when the signature field still holds the sentinel', () => {
    const kp = ml_dsa65.keygen(new Uint8Array(32).fill(7));
    const unsigned = makeDoc(SPEC_SIG_SENTINEL, SPEC_SIG_SENTINEL);
    const B = buildSignableForm(unsigned);
    const hashHex = hexEncode(sha256(B));
    // hash present but signature still sentinel
    const half = makeDoc(hashHex, SPEC_SIG_SENTINEL);
    const r = verifySpecSignature(half, base64Encode(kp.publicKey));
    expect(r.ok).toBe(false);
  });
});
