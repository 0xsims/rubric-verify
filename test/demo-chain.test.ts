/**
 * Agentic decision-chain tamper demo, as a runnable test (also serves as the
 * real-crypto end-to-end golden fixture — Item 2). Builds a 3-step ML-DSA-65
 * signed provenance chain, verifies it intact, tampers a step, asserts detection.
 * Run: npm test -- demo-chain
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { verifyChain } from '../src/verify-chain.js';
import type { StepVerifyResult } from '../src/verify-chain.js';
import { canonicalizeBytes } from '../src/canonical.js';
import { sha256, hexEncode, hexDecode, mlDsa65Verify, base64Encode, base64Decode } from '../src/crypto.js';
import type { Attestation, AttestationProvenance, DirectAttestation, TrustAnchor } from '../src/types.js';

const REGION = 'us' as const;
const ANCHOR = {
  hcs: { topic_id: '0.0.10508606', tx_id: 'demo', consensus_timestamp: '0', sequence_number: 1 },
  base: { contract_address: '0x0', tx_hash: '0x0', block_number: 1, block_timestamp: '0' },
};

function canonBytes(a: DirectAttestation): Uint8Array {
  return canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
    ...(a.provenance ? { provenance: a.provenance } : {}),
  });
}

function buildStep(
  kp: { publicKey: Uint8Array; secretKey: Uint8Array },
  id: string,
  payload: Record<string, unknown>,
  parent?: { id: string; payloadHash: string },
): { attestation: DirectAttestation; payloadHash: string } {
  const a: DirectAttestation = {
    rubric_version: '1.0',
    attestation_type: 'direct',
    attestation_id: id,
    issuer_node_region: REGION,
    issued_at: '2026-06-02T12:00:00Z',
    payload,
    publicKey: base64Encode(kp.publicKey),
    signature: 'PLACEHOLDER',
    anchors: ANCHOR,
  };
  if (parent) {
    // LEGACY-AIRLOCK GUARD (do NOT modernize): intentionally emits the pre-DAG
    // single-parent provenance shape to exercise getParents()'s back-compat branch
    // (verify-chain.ts) against a real ML-DSA-65-signed chain. Cast through unknown
    // because AttestationProvenance is now strictly {parents:[]}; this fixture
    // represents legacy on-disk data whose shape predates that type.
    a.provenance = {
      parent_attestation_id: parent.id,
      parent_payload_hash: parent.payloadHash,
      parent_issuer_region: REGION,
      relationship: 'consumed_output',
    } as unknown as AttestationProvenance;
  }
  const msg = canonBytes(a);
  a.signature = hexEncode(ml_dsa65.sign(kp.secretKey, msg));
  return { attestation: a, payloadHash: hexEncode(sha256(msg)) };
}

async function realVerifyStep(a: Attestation): Promise<StepVerifyResult> {
  try {
    const ad = a as DirectAttestation;
    const msg = canonBytes(ad);
    const ok = mlDsa65Verify(base64Decode(ad.publicKey), msg, hexDecode(ad.signature));
    return {
      verified: ok,
      details: { signature_valid: ok, hcs_anchor_confirmed: true, base_anchor_confirmed: true },
      failures: ok ? [] : ['ML-DSA-65 signature invalid'],
    };
  } catch (e) {
    return { verified: false, details: { signature_valid: false }, failures: [String(e)] };
  }
}

const DUMMY_TA = {} as unknown as TrustAnchor;

function buildChain(): DirectAttestation[] {
  const kp = ml_dsa65.keygen(new Uint8Array(32).fill(7));
  const s1 = buildStep(kp, 'step-1-retrieve', { action: 'retrieve_customer_record', customer: 'ACME-1042' });
  const s2 = buildStep(kp, 'step-2-assess', { action: 'risk_assessment', score: 0.82, model: 'risk-v3' },
    { id: s1.attestation.attestation_id, payloadHash: s1.payloadHash });
  const s3 = buildStep(kp, 'step-3-decide', { action: 'approve_credit', amount: 50000 },
    { id: s2.attestation.attestation_id, payloadHash: s2.payloadHash });
  return [s1.attestation, s2.attestation, s3.attestation];
}

describe('DEMO — agentic chain real-crypto end-to-end (Item 2 golden fixture)', () => {
  it('verifies an intact 3-step ML-DSA-65 signed provenance chain', async () => {
    const r = await verifyChain(buildChain() as Attestation[], DUMMY_TA, undefined, {
      verifyStep: realVerifyStep, workflowId: 'credit-decision-demo',
    });
    expect(r.verified).toBe(true);
    expect(r.findings).toEqual([]);
    expect(r.head).toBe('step-1-retrieve');
    expect(r.tail).toBe('step-3-decide');
  });

  it('detects tampering: altering step-2 payload breaks its signature AND step-3 link', async () => {
    const chain = buildChain();
    (chain[1]!.payload as Record<string, unknown>).score = 0.20; // doctor the record after signing
    const r = await verifyChain(chain as Attestation[], DUMMY_TA, undefined, {
      verifyStep: realVerifyStep, workflowId: 'credit-decision-demo',
    });
    expect(r.verified).toBe(false);
    // step-2's signature no longer matches its altered payload
    expect(r.findings.some((f) => f.type === 'bad_sig' && f.attestation_id === 'step-2-assess')).toBe(true);
    // step-3's provenance bound step-2's ORIGINAL hash → now breaks
    expect(r.findings.some((f) => f.type === 'break' && f.attestation_id === 'step-3-decide')).toBe(true);
  });
});
