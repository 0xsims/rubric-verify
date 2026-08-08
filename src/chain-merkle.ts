/**
 * chain-merkle.ts — the CANONICAL on-chain Merkle construction (v2.0).
 *
 * This is the construction that seals every production tiered and session
 * anchor (proven byte-for-byte against the deployed builder, 2026-08-07, and
 * pinned by the normative vectors in test/chain-conformance.standalone.ts):
 *
 *   algorithm : SHA3-256
 *   leaf_pre  : "sha3-256:" + SHA3-256( JCS({ __leafType: TYPE, ...data }) )
 *   leaf      : SHA3-256( 0x00 || bytes(hex after prefix) )   // RFC-6962 tag
 *   node      : SHA3-256( 0x01 || L || R )                    // RFC-6962 tag
 *   odd level : PROMOTE the lone node (no duplication)
 *   wrap      : SHA3-256( utf8(root_hex || root_hex) )        // single-tree forest
 *
 * The legacy modules (src/merkle.ts SHA-256; src/legacy-1x/* ratified-vector
 * construction) implement the rc2-era spec reading and DO NOT reproduce chain
 * anchors. Verifiers of real anchors MUST use this module. See Verify Spec
 * v2.0 §4.1/§4.7/§9.
 */
import { createHash } from "node:crypto";

export type ChainJson =
  | null | boolean | number | string | ChainJson[] | { [k: string]: ChainJson };

/** RFC 8785 (JCS) canonicalization — byte-identical to the deployed sealer. */
export function chainCanonicalize(v: ChainJson): string {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number") {
      if (!Number.isFinite(v)) throw new Error("JCS: non-finite number");
      if (Object.is(v, -0)) return "0";
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(chainCanonicalize).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + chainCanonicalize((v as any)[k])).join(",") + "}";
}

export type ChainLeafType =
  | "DOCUMENT_HASH" | "DATA_RECORD" | "AGENT_OUTPUT" | "HUMAN_REVIEW"
  | "MODEL_VERSION" | "IMPACT_ASSESSMENT" | "THIRD_PARTY_MODEL" | "SESSION_EVENT";

const sha3 = (b: Buffer | string): string =>
  createHash("sha3-256").update(b).digest("hex");

/** Typed leaf digest, bare hex (the "sha3-256:" prefix stripped for the wire). */
export function chainLeafDigest(type: ChainLeafType, data: ChainJson): string {
  const typed =
    data !== null && typeof data === "object" && !Array.isArray(data)
      ? { __leafType: type, ...(data as object) }
      : { __leafType: type, __data: data };
  return sha3(Buffer.from(chainCanonicalize(typed as ChainJson), "utf8"));
}

const dLeaf = (hex: string): string =>
  sha3(Buffer.concat([Buffer.from([0x00]), Buffer.from(hex, "hex")]));
const dNode = (l: string, r: string): string =>
  sha3(Buffer.concat([Buffer.from([0x01]), Buffer.from(l, "hex"), Buffer.from(r, "hex")]));

/** Single-tree forest wrap: SHA3-256 over the utf8 of root_hex twice. */
export function chainForestWrap(rootHex: string): string {
  return sha3(Buffer.from(rootHex + rootHex, "utf8"));
}

export interface ChainProofStep { position: "left" | "right"; hash: string; }

export interface ChainTree {
  root: string;                    // inner (pre-wrap) root, bare hex
  wrappedRoot: string;             // forest-wrapped root, bare hex
  leafCount: number;
  proof(index: number): ChainProofStep[];
}

/** Build the tagged promote-odd tree over typed-leaf digests (bare hex). */
export function buildChainTree(leafDigests: string[]): ChainTree {
  if (leafDigests.length === 0) throw new Error("chain tree needs at least one leaf");
  const levels: string[][] = [leafDigests.map(dLeaf)];
  while (levels[levels.length - 1]!.length > 1) {
    const cur = levels[levels.length - 1]!;
    const next: string[] = [];
    for (let i = 0; i + 1 < cur.length; i += 2) next.push(dNode(cur[i]!, cur[i + 1]!));
    if (cur.length % 2 === 1) next.push(cur[cur.length - 1]!); // PROMOTE
    levels.push(next);
  }
  const root = levels[levels.length - 1]![0]!;
  return {
    root,
    wrappedRoot: chainForestWrap(root),
    leafCount: leafDigests.length,
    proof(index: number): ChainProofStep[] {
      if (index < 0 || index >= leafDigests.length) throw new Error("proof index out of range");
      return rebuildPath(levels, index);
    },
};
}

function childToParentIndex(levelLen: number, i: number): number {
  if (levelLen % 2 === 1 && i === levelLen - 1) return Math.floor(levelLen / 2); // promoted slot
  return Math.floor(i / 2);
}
function rebuildPath(levels: string[][], leafIndex: number): ChainProofStep[] {
  const path: ChainProofStep[] = [];
  let i = leafIndex;
  for (let d = 0; d < levels.length - 1; d++) {
    const cur = levels[d]!;
    const isPromoted = cur.length % 2 === 1 && i === cur.length - 1;
    if (!isPromoted) {
      const sib = i % 2 === 0 ? i + 1 : i - 1;
      path.push({ position: sib < i ? "left" : "right", hash: cur[sib]! });
    }
    i = childToParentIndex(cur.length, i);
  }
  return path;
}

/** Fold a leaf digest up an inclusion path to the inner root (bare hex). */
export function chainFold(leafDigest: string, path: ChainProofStep[]): string {
  let cur = dLeaf(leafDigest);
  for (const s of path) cur = s.position === "left" ? dNode(s.hash, cur) : dNode(cur, s.hash);
  return cur;
}

/** Epoch/session composition (Verify Spec v2.0 §9.3). */
export function chainEpochRoot(eventDigests: string[]): string {
  return buildChainTree(eventDigests).wrappedRoot;
}
export function chainSessionRoot(epochs: { root: string; itemCount: number }[]): string {
  const leaves = epochs.map((e) =>
    chainLeafDigest("DOCUMENT_HASH", { forestRoot: e.root, itemCount: e.itemCount }));
  return buildChainTree(leaves).wrappedRoot;
}
