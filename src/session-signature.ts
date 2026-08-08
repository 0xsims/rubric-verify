/**
 * session-signature.ts — ML-DSA-65 seal signature verification (v2.0 §9.4).
 * Split from session-verify so the hash-only checks stay dependency-free.
 */
import { createHash } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

export interface SessionSignature {
  alg: string;                 // "ml-dsa-65"
  sig: string;                 // 6618 hex chars
  public_key_b64: string;      // standard-padded base64, 1952 raw bytes
  key_fp?: string;             // SHA3-256(raw key)
}

export function verifySessionSignature(sessionRoot: string, sig: SessionSignature): { ok: boolean; reason?: string } {
  if (sig.alg !== "ml-dsa-65") return { ok: false, reason: `unsupported alg ${sig.alg}` };
  if (!/^[0-9a-f]{6618}$/.test(sig.sig)) return { ok: false, reason: "signature not 6618 lowercase hex" };
  if (/[-_]/.test(sig.public_key_b64)) return { ok: false, reason: "url-safe base64 rejected" };
  const key = Buffer.from(sig.public_key_b64, "base64");
  if (Buffer.from(key).toString("base64") !== sig.public_key_b64) return { ok: false, reason: "base64 re-encode mismatch" };
  if (key.length !== 1952) return { ok: false, reason: `key ${key.length} bytes, want 1952` };
  if (sig.key_fp) {
    const fp = createHash("sha3-256").update(key).digest("hex");
    if (fp !== sig.key_fp) return { ok: false, reason: "key_fp mismatch" };
  }
  const ok = ml_dsa65.verify(new Uint8Array(key), new Uint8Array(Buffer.from(sessionRoot, "hex")), new Uint8Array(Buffer.from(sig.sig, "hex")));
  return ok ? { ok } : { ok: false, reason: "signature does not verify over root bytes" };
}

