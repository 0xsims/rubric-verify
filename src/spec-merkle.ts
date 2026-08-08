// spec-merkle.ts
//
// Spec-conformant Merkle construction per Rubric Verify Spec §7.1 and the
// ratified golden vectors (test/vectors/tiered-golden-vectors-v0_1.json,
// RATIFIED-tiered-v0_1.md, 2026-06-11).
//
// Rules (FROZEN — divergence from the ratified vectors is a defect here):
//   leaf  = SHA-256(0x00 || canonicalize(§6.3 tiered message))   [JCS/RFC 8785]
//   node  = SHA-256(0x01 || L || R)                              [byte concat]
//   odd   : lone-node promotion (NOT duplicate-last)
//   proof : sibling hashes with 'L'/'R' directions per bundle-types
//
// This module is ADDITIVE (C2.1). It does not replace merkle.ts buildTree /
// makeLeafV2, which remain in use by legacy callers (tier2 aggregation,
// human-review evidence trees). Callers migrate in C2.2/C2.3.
//
// ComplianceRef is defined here temporarily; it migrates to bundle-types.ts
// in C2.3 when TieredAttestation gains the field (spec reconciliation item).

import { createHash } from "crypto";
import { canonicalize } from "./canonical.js";
// Offline port: bundle-types dependency severed — structural aliases suffice
// for a verifier that treats records as data, not domain objects.
type ModelRef = Record<string, unknown>;
type AttestationProvenance = Record<string, unknown>;
type EvidenceRef = Record<string, unknown>;
type IssuerNodeRegion = string;

/** Customer-ASSERTED compliance metadata, §5.7 (proposed). Witness-agnostic:
 *  Rubric attests that the customer stated these values — never that the
 *  classification is correct. All fields optional. */
export interface ComplianceRef {
  risk_level?: string;
  population_group?: string;
  jurisdiction?: string[];
  event_type?: string;
}

/** Inputs to build one tiered leaf's §6.3 canonical message. */
export interface TieredLeafInput {
  attestation_id: string;
  issuer_node_region: IssuerNodeRegion;
  issued_at: string;                    // RFC 3339 UTC
  payload: Record<string, unknown>;
  provenance?: AttestationProvenance;
  evidence?: EvidenceRef[];
  model_ref?: ModelRef;
  compliance_ref?: ComplianceRef;
}

/** §6.3 tiered canonical message object. Optional siblings are OMITTED when
 *  absent (never null) — pinned by vector 4 (modelref-absent-omits-key). */
export function buildTieredLeafMessage(input: TieredLeafInput): Record<string, unknown> {
  const m: Record<string, unknown> = {
    rubric_version: "1.0",
    attestation_type: "tiered",
    attestation_id: input.attestation_id,
    issuer_node_region: input.issuer_node_region,
    issued_at: input.issued_at,
    payload: input.payload,
  };
  if (input.provenance) m["provenance"] = input.provenance;
  if (input.evidence) m["evidence"] = input.evidence;
  if (input.model_ref) m["model_ref"] = input.model_ref;
  if (input.compliance_ref) m["compliance_ref"] = input.compliance_ref;
  return m;
}

const sha256 = (buf: Buffer): Buffer => createHash("sha256").update(buf).digest();

/** leaf = SHA-256(0x00 || canonical message bytes). Returns hash + the exact
 *  canonical string (needed for payload_hash and for audit). */
export function leafHash(message: Record<string, unknown>): { hash: Buffer; canonical: string } {
  const canonical = canonicalize(message);
  const hash = sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonical, "utf8")]));
  return { hash, canonical };
}

/** node = SHA-256(0x01 || L || R), byte-level concatenation. */
export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}

export interface SpecProofStep { hash: string; dir: "L" | "R"; }

export interface SpecTree {
  root: Buffer;
  rootHex: string;
  leafCount: number;
  /** levels[0] = leaf hashes; levels[n] = root level */
  levels: Buffer[][];
}

/** Build the domain-separated tree with lone-node promotion. */
export function buildSpecTree(leaves: Buffer[]): SpecTree {
  if (leaves.length === 0) throw new Error("buildSpecTree requires >= 1 leaf");
  const levels: Buffer[][] = [leaves];
  let level = leaves;
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) next.push(nodeHash(level[i]!, level[i + 1]!));
      else next.push(level[i]!); // lone-node promotion
    }
    levels.push(next);
    level = next;
  }
  const root = level[0]!;
  return { root, rootHex: root.toString("hex"), leafCount: leaves.length, levels };
}

/** Inclusion proof for leaf at index. A promoted lone node contributes no
 *  step at that level (pinned by vector 2, odd-count case). */
export function proofForLeaf(tree: SpecTree, leafIndex: number): SpecProofStep[] {
  if (leafIndex < 0 || leafIndex >= tree.leafCount) throw new Error(`leaf index ${leafIndex} out of range`);
  const proof: SpecProofStep[] = [];
  let idx = leafIndex;
  for (let lvl = 0; lvl < tree.levels.length - 1; lvl++) {
    const level = tree.levels[lvl]!;
    const isRight = idx % 2 === 1;
    const sibIdx = isRight ? idx - 1 : idx + 1;
    if (sibIdx < level.length) {
      proof.push({ hash: level[sibIdx]!.toString("hex"), dir: isRight ? "L" : "R" });
    }
    idx = Math.floor(idx / 2);
  }
  return proof;
}

/** Walk a proof from a leaf to an expected root. */
export function verifyProof(leaf: Buffer, proof: SpecProofStep[], expectedRootHex: string): boolean {
  let h = leaf;
  for (const step of proof) {
    const sib = Buffer.from(step.hash, "hex");
    h = step.dir === "L" ? nodeHash(sib, h) : nodeHash(h, sib);
  }
  return h.toString("hex") === expectedRootHex;
}
