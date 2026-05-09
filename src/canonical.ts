/**
 * Deterministic JSON canonicalization per RFC 8785 (JSON Canonicalization Scheme),
 * with the clarifications mandated by Rubric Verify Spec v1.0.0 §6.1:
 *
 *   1. Object keys MUST be sorted lexicographically (UTF-16 code unit order).
 *   2. There MUST be no whitespace between tokens.
 *   3. Numbers MUST be serialized using the shortest representation that
 *      round-trips through IEEE 754 double-precision parsing.
 *   4. Strings MUST be UTF-8 encoded.
 *   5. Boolean values MUST be `true` or `false` (lowercase).
 *   6. The null value MUST be `null` (lowercase).
 *   7. Arrays MUST preserve their input order.
 *   8. The output MUST be UTF-8 encoded; the canonical message bytes are the
 *      UTF-8 encoding of the canonicalized string.
 *
 * This module is intentionally dependency-free.
 */

import { VerificationInputError } from './errors.js';

/**
 * Canonicalize a JSON-compatible value to its RFC 8785 form.
 *
 * @returns the canonical UTF-8 string. The caller may UTF-8-encode this to
 * obtain the byte sequence that signatures are computed over.
 */
export function canonicalize(value: unknown): string {
  return serialize(value);
}

/**
 * UTF-8-encode the canonicalization of `value`.
 *
 * Equivalent to `new TextEncoder().encode(canonicalize(value))`.
 */
export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

function serialize(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) {
    throw new VerificationInputError('cannot canonicalize undefined; use null instead');
  }

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return serializeNumber(value);
    case 'string':
      return serializeString(value);
    case 'object':
      if (Array.isArray(value)) return serializeArray(value);
      return serializeObject(value as Record<string, unknown>);
    case 'bigint':
      throw new VerificationInputError('bigint is not representable in canonical JSON');
    case 'function':
    case 'symbol':
      throw new VerificationInputError(`unsupported value type: ${typeof value}`);
    default:
      throw new VerificationInputError(`unknown value type: ${typeof value}`);
  }
}

function serializeArray(arr: unknown[]): string {
  const parts: string[] = [];
  for (const item of arr) {
    parts.push(serialize(item));
  }
  return '[' + parts.join(',') + ']';
}

function serializeObject(obj: Record<string, unknown>): string {
  // Per RFC 8785 §3.2.3: object keys are sorted by UTF-16 code unit order.
  // JavaScript's String comparison operators do exactly this on BMP strings;
  // for surrogate-pair-bearing keys we use Array.prototype.sort with the
  // default behavior (which is also UTF-16 code-unit ordering).
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const v = obj[key];
    if (v === undefined) continue; // RFC 8785: properties whose values are undefined are not serialized
    parts.push(serializeString(key) + ':' + serialize(v));
  }
  return '{' + parts.join(',') + '}';
}

/**
 * Serialize a string per RFC 8785 §3.2.2.2 / RFC 8259 §7.
 *
 * Required escapes: " \ U+0000..U+001F.
 * Non-required characters are emitted as-is (no \uXXXX escaping of printable
 * characters or non-ASCII).
 */
function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20) {
      // Control characters: shortest forms per RFC 8259, otherwise \u00XX.
      switch (c) {
        case 0x08:
          out += '\\b';
          break;
        case 0x09:
          out += '\\t';
          break;
        case 0x0a:
          out += '\\n';
          break;
        case 0x0c:
          out += '\\f';
          break;
        case 0x0d:
          out += '\\r';
          break;
        default:
          out += '\\u' + c.toString(16).padStart(4, '0');
      }
    } else if (c === 0x22) {
      out += '\\"';
    } else if (c === 0x5c) {
      out += '\\\\';
    } else {
      out += s[i];
    }
  }
  out += '"';
  return out;
}

/**
 * Serialize a number per RFC 8785 §3.2.2.3 — shortest round-tripping form.
 *
 * Per the spec, NaN and ±Infinity are NOT representable in JSON. We reject them.
 * For finite numbers, JavaScript's String(n) produces the shortest round-tripping
 * decimal representation per ECMA-262 (Number.prototype.toString), with the
 * following caveats normalized below to match RFC 8785:
 *
 *   - Integer-valued floats: emit without ".0" suffix (e.g. 1, not 1.0). [matches String(n)]
 *   - Negative zero: serialized as "0" per RFC 8785 §3.2.2.3. [String(n) yields "0" already]
 *   - Exponent form: lowercase 'e', no '+' before positive exponents. [matches String(n)]
 */
function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new VerificationInputError(`non-finite number is not representable in JSON: ${n}`);
  }
  if (Object.is(n, -0)) return '0';
  // String(n) in V8/JSC/SpiderMonkey produces the shortest round-tripping
  // representation per ECMA-262 spec, which aligns with RFC 8785 §3.2.2.3.
  return String(n);
}
