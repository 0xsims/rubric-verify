#!/usr/bin/env node
/**
 * Rubric — agentic decision-chain tamper demo (presentation build).
 * Self-contained, offline, real ML-DSA-65. Run: node rubric-chain-demo.mjs
 * (requires `npm run build` first — imports from dist/esm/)
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { verifyChain } from './dist/esm/verify-chain.js';
import { canonicalizeBytes } from './dist/esm/canonical.js';
import { sha256, hexEncode, hexDecode, mlDsa65Verify, base64Encode, base64Decode } from './dist/esm/crypto.js';

const REGION = 'us';
const ANCHOR = {
  hcs: { topic_id: '0.0.10508606', tx_id: 'demo', consensus_timestamp: '0', sequence_number: 1 },
  base: { contract_address: '0x0', tx_hash: '0x0', block_number: 1, block_timestamp: '0' },
};
const canon = (a) => canonicalizeBytes({
  rubric_version: a.rubric_version, attestation_type: a.attestation_type,
  attestation_id: a.attestation_id, issuer_node_region: a.issuer_node_region,
  issued_at: a.issued_at, payload: a.payload,
  ...(a.provenance ? { provenance: a.provenance } : {}),
});
function buildStep(kp, id, payload, parent) {
  const a = { rubric_version: '1.0', attestation_type: 'direct', attestation_id: id,
    issuer_node_region: REGION, issued_at: '2026-06-02T12:00:00Z', payload,
    publicKey: base64Encode(kp.publicKey), anchors: ANCHOR };
  if (parent) a.provenance = { parent_attestation_id: parent.id,
    parent_payload_hash: parent.payloadHash, parent_issuer_region: REGION,
    relationship: 'consumed_output' };
  const msg = canon(a);
  a.signature = hexEncode(ml_dsa65.sign(kp.secretKey, msg));
  return { attestation: a, payloadHash: hexEncode(sha256(msg)) };
}
async function realVerifyStep(a) {
  try {
    const ok = mlDsa65Verify(base64Decode(a.publicKey), canon(a), hexDecode(a.signature));
    return { verified: ok, details: { signature_valid: ok, hcs_anchor_confirmed: true, base_anchor_confirmed: true }, failures: ok ? [] : ['ML-DSA-65 signature invalid'] };
  } catch (e) { return { verified: false, details: { signature_valid: false }, failures: [String(e)] }; }
}
const L = () => console.log('─'.repeat(72));
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function main() {
  console.log('\n\x1b[1mRUBRIC — AGENTIC DECISION-CHAIN TAMPER DEMO\x1b[0m');
  console.log('Post-quantum (ML-DSA-65) signed provenance chain · independent verification · offline\n');
  L();
  console.log('\nAn AI agent runs a 3-step credit decision. Each step is signed and');
  console.log('cryptographically linked to the previous one:\n');
  await sleep(300);
  const kp = ml_dsa65.keygen();
  const s1 = buildStep(kp, 'step-1-retrieve', { action: 'retrieve_customer_record', customer: 'ACME-1042' });
  console.log(`  ✓ step-1-retrieve   hash ${s1.payloadHash.slice(0,20)}…`); await sleep(250);
  const s2 = buildStep(kp, 'step-2-assess', { action: 'risk_assessment', score: 0.82, model: 'risk-v3' }, { id: s1.attestation.attestation_id, payloadHash: s1.payloadHash });
  console.log(`  ✓ step-2-assess     hash ${s2.payloadHash.slice(0,20)}…   ← links step-1`); await sleep(250);
  const s3 = buildStep(kp, 'step-3-decide', { action: 'approve_credit', amount: 50000 }, { id: s2.attestation.attestation_id, payloadHash: s2.payloadHash });
  console.log(`  ✓ step-3-decide     hash ${s3.payloadHash.slice(0,20)}…   ← links step-2`); await sleep(250);
  const chain = [s1.attestation, s2.attestation, s3.attestation];
  L();
  console.log('\n\x1b[1m[1] VERIFY THE INTACT CHAIN\x1b[0m\n'); await sleep(300);
  const r1 = await verifyChain(chain, {}, undefined, { verifyStep: realVerifyStep, workflowId: 'credit-decision-demo' });
  console.log(`    verified:  \x1b[32m${r1.verified}\x1b[0m`);
  console.log(`    chain:     ${r1.head} → ${r1.tail}  (${r1.step_count} steps)`);
  console.log(`    findings:  ${r1.findings.length === 0 ? 'none — every signature + every link valid' : JSON.stringify(r1.findings)}`); await sleep(600);
  L();
  console.log('\n\x1b[1m[2] TAMPER — someone alters step-2 AFTER the fact\x1b[0m\n');
  console.log('    risk score  0.82  →  0.20   (doctoring the record post-decision)\n'); await sleep(500);
  const t = JSON.parse(JSON.stringify(chain));
  t[1].payload.score = 0.20;
  const r2 = await verifyChain(t, {}, undefined, { verifyStep: realVerifyStep, workflowId: 'credit-decision-demo' });
  console.log(`    verified:  \x1b[31m${r2.verified}\x1b[0m`);
  console.log(`    findings:`);
  for (const f of r2.findings) console.log(`      \x1b[31m•\x1b[0m [${f.type}] ${f.attestation_id ?? ''} — ${f.detail}`);
  await sleep(300);
  L();
  console.log('\n\x1b[1mWHAT JUST HAPPENED\x1b[0m');
  console.log('  • step-2\'s signature no longer matches its altered payload  → \x1b[31mbad_sig\x1b[0m');
  console.log('  • step-3\'s link to step-2\'s ORIGINAL hash is now broken      → \x1b[31mbreak\x1b[0m');
  console.log('  • The tamper is caught even though the attacker had full data access.');
  console.log('  • Verification is independent — no trust in the operator required.\n');
  console.log('  Boundary: proves the \x1b[1msubmitted\x1b[0m chain is intact. Does not assert the');
  console.log('  agent submitted every step — gaps in submission are themselves detectable.\n');
}
main().catch(e => { console.error(e); process.exit(1); });
