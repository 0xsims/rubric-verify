/**
 * Canonicalization tests covering RFC 8785 conformance and the spec §6.2 example.
 */

import { canonicalize, canonicalizeBytes } from '../src/canonical.js';
import { VerificationInputError } from '../src/errors.js';

describe('canonicalize', () => {
  it('matches the spec §6.2 reference example', () => {
    expect(canonicalize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it('produces 13-byte UTF-8 output for the reference example', () => {
    expect(canonicalizeBytes({ b: 2, a: 1 }).length).toBe(13);
  });

  it('emits null/true/false in lowercase', () => {
    expect(canonicalize({ a: null, b: true, c: false })).toBe(
      '{"a":null,"b":true,"c":false}',
    );
  });

  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('sorts object keys lexicographically (UTF-16 code unit)', () => {
    expect(canonicalize({ z: 1, A: 2, a: 3 })).toBe('{"A":2,"a":3,"z":1}');
  });

  it('serializes nested structures recursively', () => {
    expect(canonicalize({ x: { b: 2, a: [3, 2, 1] } })).toBe(
      '{"x":{"a":[3,2,1],"b":2}}',
    );
  });

  it('escapes required control characters and quote/backslash', () => {
    expect(canonicalize('a"b\\c\n')).toBe('"a\\"b\\\\c\\n"');
  });

  it('emits 4-hex unicode escape for non-shorthand control chars', () => {
    expect(canonicalize('\x01')).toBe('"\\u0001"');
  });

  it('does not escape non-ASCII printable characters', () => {
    // RFC 8785 §3.2.2.2 — non-control characters MUST NOT be escaped.
    expect(canonicalize('café — ñ')).toBe('"café — ñ"');
  });

  it('serializes integers without a fractional part', () => {
    expect(canonicalize(42)).toBe('42');
    expect(canonicalize(0)).toBe('0');
    expect(canonicalize(-7)).toBe('-7');
  });

  it('serializes -0 as "0"', () => {
    expect(canonicalize(-0)).toBe('0');
  });

  it('rejects undefined values', () => {
    expect(() => canonicalize(undefined)).toThrow(VerificationInputError);
  });

  it('rejects NaN and Infinity', () => {
    expect(() => canonicalize(Number.NaN)).toThrow(VerificationInputError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(VerificationInputError);
    expect(() => canonicalize(Number.NEGATIVE_INFINITY)).toThrow(VerificationInputError);
  });

  it('rejects bigint', () => {
    expect(() => canonicalize(BigInt(1))).toThrow(VerificationInputError);
  });

  it('omits undefined object properties (per RFC 8785 §3.2.3)', () => {
    expect(canonicalize({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
  });

  it('canonicalizes a representative attestation message', () => {
    const msg = {
      rubric_version: '1.0',
      attestation_type: 'direct',
      attestation_id: 'att_2026_04_20_a1b2c3d4',
      issuer_node_region: 'us',
      issued_at: '2026-04-20T14:32:01Z',
      payload: { decision: 'approved', actor: 'model-v1' },
    };
    const c = canonicalize(msg);
    // Sanity: keys appear in sorted order at every level.
    expect(c).toBe(
      '{"attestation_id":"att_2026_04_20_a1b2c3d4",' +
        '"attestation_type":"direct",' +
        '"issued_at":"2026-04-20T14:32:01Z",' +
        '"issuer_node_region":"us",' +
        '"payload":{"actor":"model-v1","decision":"approved"},' +
        '"rubric_version":"1.0"}',
    );
  });
});
