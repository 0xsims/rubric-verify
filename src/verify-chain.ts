/**
 * Workflow chain verification.
 *
 * Verifies that a sequence of attestations linked by signed `provenance` forms
 * an intact, unbroken, untampered chain — and detects tampering, broken links,
 * and gaps.
 *
 * HONEST BOUNDARY (structural, not optional): this proves the SUBMITTED chain is
 * intact. It does NOT prove the agent submitted everything it did. `scope` is
 * always 'submitted-chain-integrity'; findings describe the submitted record,
 * never "the agent's complete activity". Submission-completeness is the
 * integrator's responsibility; this makes any post-submission gap/tamper
 * cryptographically detectable.
 *
 * Per-step verification reuses the top-level `verify()` (signature + anchors +
 * trust-anchor selection) by default, so chain verification inherits all proven
 * per-step fail-closed behavior. The chain layer adds linkage, gap, and
 * reachability checks over the `provenance` DAG, and aggregates per-step results.
 */

import { verify } from './verify.js';
import { canonicalizeBytes } from './canonical.js';
import { hexEqual, hexEncode, sha256 } from './crypto.js';
import type {
  Attestation,
  TrustAnchor,
  AnchorAccess,
  VerifyDetails,
} from './types.js';

export interface ChainFinding {
  type:
    | 'tamper'
    | 'break'
    | 'gap'
    | 'unanchored'
    | 'bad_sig'
    | 'undersubmitted';
  attestation_id?: string;
  detail: string;
}

export interface ChainVerifyResult {
  verified: boolean;
  workflow_id?: string;
  step_count: number;
  head: string | null;
  tail: string | null;
  findings: ChainFinding[];
  scope: 'submitted-chain-integrity';
}

/** Result shape returned by a per-step verifier (subset of VerifyResult). */
export interface StepVerifyResult {
  verified: boolean;
  details: VerifyDetails;
  failures: string[];
}

/** A per-step verifier. Defaults to the real verify(); injectable for testing. */
export type StepVerifier = (a: Attestation) => Promise<StepVerifyResult>;

export interface ChainVerifyOptions {
  workflowId?: string;
  expectedCount?: number;
  /** Skip per-step cryptographic verification (structure/linkage only). Default false. */
  skipStepVerification?: boolean;
  /** Injectable per-step verifier (testing). Defaults to verify() with the supplied anchor/access. */
  verifyStep?: StepVerifier;
}

function makeResult(
  verified: boolean,
  stepCount: number,
  head: string | null,
  tail: string | null,
  findings: ChainFinding[],
  workflowId?: string,
): ChainVerifyResult {
  return {
    verified,
    ...(workflowId ? { workflow_id: workflowId } : {}),
    step_count: stepCount,
    head,
    tail,
    findings,
    scope: 'submitted-chain-integrity',
  };
}

/**
 * Recompute an attestation's canonical payload hash exactly as the signer did
 * and verify-direct does: JCS canonical message over the signed fields
 * (including provenance/evidence when present), SHA-256, hex. Recomputed — never
 * read from a stored field — so linkage checks are tamper-evident.
 */
function canonicalHashHex(a: Attestation): string {
  const bytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
    ...(a.provenance ? { provenance: a.provenance } : {}),
    ...(a.evidence ? { evidence: a.evidence } : {}),
  });
  return hexEncode(sha256(bytes));
}

export async function verifyChain(
  attestations: Attestation[],
  trustAnchor: TrustAnchor | TrustAnchor[],
  access?: AnchorAccess,
  opts?: ChainVerifyOptions,
): Promise<ChainVerifyResult> {
  const wf = opts?.workflowId;
  const findings: ChainFinding[] = [];

  // --- fail-closed: empty input ---
  if (!Array.isArray(attestations) || attestations.length === 0) {
    return makeResult(false, 0, null, null,
      [{ type: 'gap', detail: 'empty chain: no attestations supplied' }], wf);
  }

  // --- index by attestation_id; detect duplicates (fail-closed) ---
  const index = new Map<string, Attestation>();
  for (const a of attestations) {
    if (index.has(a.attestation_id)) {
      findings.push({
        type: 'tamper',
        attestation_id: a.attestation_id,
        detail: `duplicate attestation_id in chain: ${a.attestation_id}`,
      });
    }
    index.set(a.attestation_id, a);
  }

  // --- identify heads (no provenance) ---
  const heads = attestations.filter((a) => !a.provenance);
  if (heads.length === 0) {
    findings.push({ type: 'gap', detail: 'no chain head: every attestation has a provenance parent (cycle or orphaned)' });
    return makeResult(false, attestations.length, null, null, findings, wf);
  }
  if (heads.length > 1) {
    findings.push({
      type: 'gap',
      detail: `ambiguous chain: ${heads.length} heads (attestations with no provenance): ${heads.map((h) => h.attestation_id).join(', ')}`,
    });
  }
  const head = heads[0]!;

  // --- reachability walk from head, following children (parent -> child) ---
  const childrenOf = new Map<string, string[]>();
  for (const a of attestations) {
    const parentId = a.provenance?.parent_attestation_id;
    if (parentId) {
      const arr = childrenOf.get(parentId) ?? [];
      arr.push(a.attestation_id);
      childrenOf.set(parentId, arr);
    }
  }

  const reachable = new Set<string>();
  const stack: string[] = [head.attestation_id];
  let tail: string | null = head.attestation_id;
  let maxDepth = -1;
  const depth = new Map<string, number>([[head.attestation_id, 0]]);
  while (stack.length) {
    const id = stack.pop()!;
    if (reachable.has(id)) continue; // cycle guard
    reachable.add(id);
    const d = depth.get(id) ?? 0;
    if (d > maxDepth) { maxDepth = d; tail = id; }
    for (const childId of childrenOf.get(id) ?? []) {
      if (!reachable.has(childId)) {
        depth.set(childId, d + 1);
        stack.push(childId);
      }
    }
  }

  // --- gap: any attestation not reachable from head ---
  for (const a of attestations) {
    if (!reachable.has(a.attestation_id)) {
      findings.push({
        type: 'gap',
        attestation_id: a.attestation_id,
        detail: `unreachable from head: ${a.attestation_id} (broken or missing provenance link)`,
      });
    }
  }

  // --- linkage hash-checks (tamper-evidence) ---
  for (const a of attestations) {
    const prov = a.provenance;
    if (!prov) continue;
    const parent = index.get(prov.parent_attestation_id);
    if (!parent) continue; // missing parent => gap already recorded
    const actualParentHash = canonicalHashHex(parent);
    if (!hexEqual(prov.parent_payload_hash, actualParentHash)) {
      findings.push({
        type: 'break',
        attestation_id: a.attestation_id,
        detail: `provenance.parent_payload_hash does not match recomputed hash of parent ${prov.parent_attestation_id}`,
      });
    }
  }

  // --- Layer 4: per-step cryptographic verification ---
  // Each step is verified via verify() (signature + anchors + trust-anchor),
  // or an injected verifyStep for testing. Failures classify into bad_sig /
  // unanchored / tamper. This is fail-closed: any step failing => chain fails.
  if (!opts?.skipStepVerification) {
    const stepVerifier: StepVerifier =
      opts?.verifyStep ?? ((a) => verify({ attestation: a, trustAnchor, access }));
    for (const a of attestations) {
      let res: StepVerifyResult;
      try {
        res = await stepVerifier(a);
      } catch (e) {
        findings.push({
          type: 'tamper',
          attestation_id: a.attestation_id,
          detail: `per-step verification threw: ${(e as Error).message}`,
        });
        continue;
      }
      if (!res.verified) {
        const d = res.details || {};
        let type: ChainFinding['type'] = 'tamper';
        if (d.signature_valid === false) type = 'bad_sig';
        else if (d.hcs_anchor_confirmed === false && d.base_anchor_confirmed === false) type = 'unanchored';
        findings.push({
          type,
          attestation_id: a.attestation_id,
          detail: `per-step verification failed: ${(res.failures || []).join('; ') || 'no detail'}`,
        });
      }
    }
  }

  // --- expectedCount (honest undersubmission, not a claim about agent activity) ---
  if (typeof opts?.expectedCount === 'number' && reachable.size < opts.expectedCount) {
    findings.push({
      type: 'undersubmitted',
      detail: `reachable steps (${reachable.size}) fewer than caller-asserted expectedCount (${opts.expectedCount})`,
    });
  }

  const verified = findings.length === 0;
  return makeResult(verified, attestations.length, head.attestation_id, tail, findings, wf);
}
