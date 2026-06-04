import { verifyChain } from '../src/verify-chain.js';
import type { StepVerifyResult } from '../src/verify-chain.js';
import { canonicalizeBytes } from '../src/canonical.js';
import { sha256, hexEncode } from '../src/crypto.js';
import type { Attestation, DirectAttestation, TrustAnchor } from '../src/types.js';

function node(id: string, parent?: { id: string; payloadHash: string }): DirectAttestation {
  const a: DirectAttestation = {
    rubric_version: '1.0',
    attestation_type: 'direct',
    attestation_id: id,
    issuer_node_region: 'us',
    issued_at: '2026-04-20T14:32:01Z',
    payload: { step: id },
    publicKey: 'placeholder',
    signature: 'placeholder',
    anchors: {
      hcs: { topic_id: '0.0.1', tx_id: 't', consensus_timestamp: '0', sequence_number: 1 },
      base: { contract_address: '0x0', tx_hash: '0x0', block_number: 1, block_timestamp: '0' },
    },
  };
  if (parent) {
    a.provenance = {
      parents: [
        {
          parent_attestation_id: parent.id,
          parent_payload_hash: parent.payloadHash,
          parent_issuer_region: 'us',
          relationship: 'consumed_output',
        },
      ],
    };
  }
  return a;
}

function nodeHash(a: DirectAttestation): string {
  const bytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
    ...(a.provenance ? { provenance: a.provenance } : {}),
  });
  return hexEncode(sha256(bytes));
}

// Multi-parent node: emits new-shape provenance with N parent edges (a merge/fan-in).
function nodeMulti(
  id: string,
  parents: { id: string; payloadHash: string }[],
): DirectAttestation {
  const a: DirectAttestation = {
    rubric_version: '1.0',
    attestation_type: 'direct',
    attestation_id: id,
    issuer_node_region: 'us',
    issued_at: '2026-04-20T14:32:01Z',
    payload: { step: id },
    publicKey: 'placeholder',
    signature: 'placeholder',
    anchors: {
      hcs: { topic_id: '0.0.1', tx_id: 't', consensus_timestamp: '0', sequence_number: 1 },
      base: { contract_address: '0x0', tx_hash: '0x0', block_number: 1, block_timestamp: '0' },
    },
  };
  a.provenance = {
    parents: parents.map((pp) => ({
      parent_attestation_id: pp.id,
      parent_payload_hash: pp.payloadHash,
      parent_issuer_region: 'us' as const,
      relationship: 'aggregated_from' as const,
    })),
  };
  return a;
}

const DUMMY_TA = {} as unknown as TrustAnchor;
const SKIP = { skipStepVerification: true } as const;

function stubVerifier(badIds: Record<string, Partial<StepVerifyResult['details']>> = {}) {
  return async (a: Attestation): Promise<StepVerifyResult> => {
    if (a.attestation_id in badIds) {
      return { verified: false, details: badIds[a.attestation_id] || {}, failures: [`stub failure for ${a.attestation_id}`] };
    }
    return { verified: true, details: { signature_valid: true }, failures: [] };
  };
}

describe('verifyChain — Layer 2 structure', () => {
  it('fails closed on an empty chain', async () => {
    const r = await verifyChain([], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(false);
    expect(r.step_count).toBe(0);
    expect(r.head).toBeNull();
    expect(r.findings.some((f) => f.type === 'gap')).toBe(true);
    expect(r.scope).toBe('submitted-chain-integrity');
  });
  it('treats a single head-only attestation as structurally intact', async () => {
    const a = node('A');
    const r = await verifyChain([a], DUMMY_TA, undefined, SKIP);
    expect(r.step_count).toBe(1);
    expect(r.head).toBe('A');
    expect(r.tail).toBe('A');
    expect(r.findings).toEqual([]);
    expect(r.verified).toBe(true);
  });
  it('walks a 3-step linear chain and finds head/tail', async () => {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: 'hashA' });
    const c = node('C', { id: 'B', payloadHash: 'hashB' });
    const r = await verifyChain([c, a, b] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.step_count).toBe(3);
    expect(r.head).toBe('A');
    expect(r.tail).toBe('C');
    expect(r.findings.some((f) => f.type === 'gap')).toBe(false);
  });
  it('flags an orphaned node as a gap', async () => {
    const a = node('A');
    const orphan = node('X', { id: 'MISSING_PARENT', payloadHash: 'h' });
    const r = await verifyChain([a, orphan] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'gap' && f.attestation_id === 'X')).toBe(true);
  });
  it('flags multiple heads as ambiguous', async () => {
    const a = node('A');
    const b = node('B');
    const r = await verifyChain([a, b] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'gap' && /ambiguous/.test(f.detail))).toBe(true);
  });
  it('flags a duplicate attestation_id', async () => {
    const a1 = node('A');
    const a2 = node('A');
    const r = await verifyChain([a1, a2] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'tamper' && /duplicate/.test(f.detail))).toBe(true);
  });
});

describe('verifyChain — Layer 3 linkage', () => {
  it('passes a chain where each link binds the correct parent hash', async () => {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: nodeHash(a) });
    const c = node('C', { id: 'B', payloadHash: nodeHash(b) });
    const r = await verifyChain([a, b, c] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.findings.filter((f) => f.type === 'break')).toEqual([]);
    expect(r.verified).toBe(true);
  });
  it('detects a break on WRONG parent hash', async () => {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: nodeHash(a) });
    const c = node('C', { id: 'B', payloadHash: 'f'.repeat(64) });
    const r = await verifyChain([a, b, c] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'break' && f.attestation_id === 'C')).toBe(true);
  });
  it('detects a break when a parent is altered after linking', async () => {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: nodeHash(a) });
    const c = node('C', { id: 'B', payloadHash: nodeHash(b) });
    (b.payload as Record<string, unknown>)['step'] = 'TAMPERED';
    const r = await verifyChain([a, b, c] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'break' && f.attestation_id === 'C')).toBe(true);
  });
});

describe('verifyChain — Layer 4 per-step verification', () => {
  function goodChain(): DirectAttestation[] {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: nodeHash(a) });
    const c = node('C', { id: 'B', payloadHash: nodeHash(b) });
    return [a, b, c];
  }
  it('verifies a fully-valid chain when every step passes', async () => {
    const r = await verifyChain(goodChain() as Attestation[], DUMMY_TA, undefined, { verifyStep: stubVerifier() });
    expect(r.verified).toBe(true);
    expect(r.findings).toEqual([]);
  });
  it('flags bad_sig when a step signature is invalid', async () => {
    const r = await verifyChain(goodChain() as Attestation[], DUMMY_TA, undefined, { verifyStep: stubVerifier({ B: { signature_valid: false } }) });
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'bad_sig' && f.attestation_id === 'B')).toBe(true);
  });
  it('flags unanchored when both anchors unconfirmed', async () => {
    const r = await verifyChain(goodChain() as Attestation[], DUMMY_TA, undefined, { verifyStep: stubVerifier({ C: { hcs_anchor_confirmed: false, base_anchor_confirmed: false } }) });
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'unanchored' && f.attestation_id === 'C')).toBe(true);
  });
  it('fails a structurally-broken chain even if every step verifies', async () => {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: nodeHash(a) });
    const c = node('C', { id: 'B', payloadHash: 'f'.repeat(64) });
    const r = await verifyChain([a, b, c] as Attestation[], DUMMY_TA, undefined, { verifyStep: stubVerifier() });
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'break')).toBe(true);
  });
  it('flags undersubmitted when reachable < expectedCount', async () => {
    const r = await verifyChain(goodChain() as Attestation[], DUMMY_TA, undefined, { verifyStep: stubVerifier(), expectedCount: 5 });
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'undersubmitted')).toBe(true);
  });
});


describe('verifyChain — DAG multi-parent (fan-in / diamond)', () => {
  it('verifies a diamond: A->B, A->C, {B,C}->D, single sink', async () => {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: nodeHash(a) });
    const c = node('C', { id: 'A', payloadHash: nodeHash(a) });
    const d = nodeMulti('D', [
      { id: 'B', payloadHash: nodeHash(b) },
      { id: 'C', payloadHash: nodeHash(c) },
    ]);
    const r = await verifyChain([a, b, c, d] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(true);
    expect(r.findings.filter((f) => f.type === 'break')).toEqual([]);
    expect(r.step_count).toBe(4);
    expect(r.head).toBe('A');
    expect(r.tail).toBe('D');
  });

  it('detects a break when one parent edge of a merge binds a wrong hash', async () => {
    const a = node('A');
    const b = node('B', { id: 'A', payloadHash: nodeHash(a) });
    const c = node('C', { id: 'A', payloadHash: nodeHash(a) });
    const d = nodeMulti('D', [
      { id: 'B', payloadHash: nodeHash(b) },
      { id: 'C', payloadHash: 'f'.repeat(64) }, // wrong hash on the C edge
    ]);
    const r = await verifyChain([a, b, c, d] as Attestation[], DUMMY_TA, undefined, SKIP);
    expect(r.verified).toBe(false);
    expect(r.findings.some((f) => f.type === 'break' && f.attestation_id === 'D')).toBe(true);
  });
});
