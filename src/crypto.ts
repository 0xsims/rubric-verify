/**
 * Cryptographic primitive wrappers.
 *
 * Spec §4:
 *   - Hash function: SHA-256 (RFC 6234).
 *   - Signature scheme: ML-DSA-65 (FIPS 204), deterministic variant.
 *     Public keys: 1952 bytes. Signatures: 3293 bytes.
 *   - Threshold signatures: aggregated form is structurally identical to
 *     a non-aggregated ML-DSA-65 signature; verified with the same primitive.
 *
 * Trust anchor signatures use Ed25519 (the Rubric Founder Key).
 *
 * All primitives are implemented via the @noble/* libraries — single, audited,
 * dependency-free reference implementations.
 */

import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { keccak_256 as nobleKeccak256 } from '@noble/hashes/sha3';
import { ed25519 } from '@noble/curves/ed25519';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';

/** ML-DSA-65 public key length per FIPS 204. */
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;

/** ML-DSA-65 signature length per FIPS 204. */
export const ML_DSA_65_SIGNATURE_BYTES = 3293;

/** Compute SHA-256 of `data`. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** Compute Keccak-256 (used to derive Ethereum event topic selectors). */
export function keccak256(data: Uint8Array): Uint8Array {
  return nobleKeccak256(data);
}

/**
 * Verify an ML-DSA-65 signature.
 *
 * Returns false (not throws) for any malformed input — wrong key length,
 * wrong signature length, structural decode failure inside the primitive.
 * This mirrors spec §14.8 (truncated signature) which mandates `verified = false`
 * without invoking the verify primitive on malformed input.
 */
export function mlDsa65Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== ML_DSA_65_PUBLIC_KEY_BYTES) return false;
  if (signature.length !== ML_DSA_65_SIGNATURE_BYTES) return false;
  try {
    return ml_dsa65.verify(publicKey, message, signature);
  } catch {
    return false;
  }
}

/**
 * Verify an Ed25519 signature (used for trust anchor publication signatures).
 *
 * Returns false on any malformed input rather than throwing.
 */
export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32) return false;
  if (signature.length !== 64) return false;
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Encoding helpers                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Decode a hex string to bytes. Accepts optional `0x` prefix; rejects odd-length
 * inputs and non-hex characters.
 */
export function hexDecode(hex: string): Uint8Array {
  let s = hex;
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
  if (s.length % 2 !== 0) {
    throw new Error(`invalid hex length: ${s.length}`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const high = hexNibble(s.charCodeAt(2 * i));
    const low = hexNibble(s.charCodeAt(2 * i + 1));
    if (high < 0 || low < 0) throw new Error(`invalid hex character at index ${2 * i}`);
    out[i] = (high << 4) | low;
  }
  return out;
}

function hexNibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

/** Encode bytes to lowercase hex string (no `0x` prefix). */
export function hexEncode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] as number;
    out += (b >>> 4).toString(16) + (b & 0x0f).toString(16);
  }
  return out;
}

/**
 * Decode a base64 string to bytes. Accepts standard base64 only (not URL-safe).
 * Padding is required.
 */
export function base64Decode(b64: string): Uint8Array {
  // Use Node's Buffer if available (faster, validates), else atob fallback.
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(b64, 'base64');
    // Buffer.from with 'base64' silently ignores invalid chars; validate by re-encoding.
    if (buf.toString('base64').replace(/=+$/, '') !== b64.replace(/=+$/, '')) {
      throw new Error('invalid base64');
    }
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  // Browser fallback.
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Encode bytes to standard base64 (with padding). */
export function base64Encode(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin);
}

/**
 * Concatenate two byte arrays. Avoids spread to keep allocations predictable
 * for hot paths (Merkle internal-node hashing).
 */
export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Concatenate three byte arrays — used for Merkle internal node computation:
 * `internal(L, R) = SHA-256(0x01 || L || R)` (spec §7.2).
 */
export function concatBytes3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
  return out;
}

/** Constant-time byte-array equality. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

/** Hex-string equality, case-insensitive, optionally tolerating `0x` prefix. */
export function hexEqual(a: string, b: string): boolean {
  const norm = (s: string): string => {
    let x = s.toLowerCase();
    if (x.startsWith('0x')) x = x.slice(2);
    return x;
  };
  return norm(a) === norm(b);
}
