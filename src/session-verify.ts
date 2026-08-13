/**
 * session-verify.ts — Session Attestation verification (Verify Spec v1.0.0-rc2 §9.7).
 *
 * Pure functions over fetched JSON: no network, no trust in the operator.
 * The four checks of §9.7:
 *   1. leaf bytes  -> leaf_digest      (typed SESSION_EVENT digest)
 *   2. leaf_digest -> epoch_root       (fold leaf_path, forest wrap)
 *   3. epoch       -> session_root     (DOCUMENT_HASH{forestRoot,itemCount} leaf,
 *                                       fold epoch_path, forest wrap)
 *   4. session_root == manifest root == anchor payload_hash (caller supplies the
 *      mirror message payload); ML-DSA-65 signature over ROOT BYTES.
 */
import { createHash } from "node:crypto";
import {
  chainLeafDigest, chainFold, chainForestWrap, chainCanonicalize as jcs,
  type ChainProofStep, type ChainJson,
} from "./chain-merkle.js";

export interface SessionProof {
  ses: string;
  seq: number;
  leaf: Record<string, ChainJson>;
  leaf_digest: string;
  leaf_path: ChainProofStep[];
  epoch_root: string;
  epoch_leaf_count: number;
  epoch_index?: number;
  epoch_path: ChainProofStep[];
  session_root: string;
}

export interface SessionProofResult {
  ok: boolean;
  checks: { name: string; ok: boolean; detail?: string | undefined }[];
}

export function verifySessionProof(p: SessionProof): SessionProofResult {
  const checks: SessionProofResult["checks"] = [];
  const add = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail });

  const leafDigest = chainLeafDigest("SESSION_EVENT", p.leaf as ChainJson);
  add("leaf-digest", leafDigest === p.leaf_digest,
    leafDigest === p.leaf_digest ? undefined : `recomputed ${leafDigest}`);

  const epochRoot = chainForestWrap(chainFold(p.leaf_digest, p.leaf_path));
  add("epoch-inclusion", epochRoot === p.epoch_root,
    epochRoot === p.epoch_root ? undefined : `recomputed ${epochRoot}`);

  const epochLeaf = chainLeafDigest("DOCUMENT_HASH", {
    forestRoot: p.epoch_root, itemCount: p.epoch_leaf_count,
  });
  const sessionRoot = chainForestWrap(chainFold(epochLeaf, p.epoch_path));
  add("session-inclusion", sessionRoot === p.session_root,
    sessionRoot === p.session_root ? undefined : `recomputed ${sessionRoot}`);

  return { ok: checks.every((c) => c.ok), checks };
}

/** Chain-rule check over a contiguous event slice (prev = SHA3(JCS(prior record))). */
export function verifyEventChain(events: Record<string, ChainJson>[]): { ok: boolean; breakAt?: number } {
  for (let i = 0; i < events.length; i++) {
    const want = i === 0 ? null
      : createHash("sha3-256")
          .update(Buffer.from(jcs(events[i - 1]! as ChainJson), "utf8")).digest("hex");
    if ((events[i]!.prev ?? null) !== want) return { ok: false, breakAt: i };
  }
  return { ok: true };
}

/** §9.5: the decoded HCS mirror message must commit to this exact root. */
export function verifyAnchorPayload(sessionRoot: string, anchorMessage: {
  kind?: string; ses?: string; payload_hash?: string;
}, ses?: string): { ok: boolean; reason?: string } {
  if (anchorMessage.kind !== "rsa-session-close") return { ok: false, reason: `kind ${anchorMessage.kind}` };
  if (ses && anchorMessage.ses !== ses) return { ok: false, reason: "session id mismatch" };
  if (anchorMessage.payload_hash !== sessionRoot) return { ok: false, reason: "payload_hash != session_root" };
  return { ok: true };
}
