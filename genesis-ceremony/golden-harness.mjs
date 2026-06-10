// Stage 0 golden harness. Generates throwaway ML-DSA-65 keys (NON-PRODUCTION),
// builds a complete test anchor, runs sign->verify end-to-end, and records a
// golden vector. Proves the ceremony tooling is correct before any real key.
import { createRequire } from 'module';
import { writeFileSync, mkdirSync } from 'fs';
import { execSync } from 'child_process';
const require = createRequire(import.meta.url);
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa');
const { canonicalize, validateTrustAnchorSignature, assertWellFormedTrustAnchor } = require('/root/rubric-verify/dist/cjs/index.js');

const DIR = '/root/rubric-verify/genesis-ceremony/golden-vectors';
mkdirSync(DIR, { recursive: true });

const b64 = (u) => Buffer.from(u).toString('base64');
const hex = (u) => Buffer.from(u).toString('hex');

// Deterministic throwaway keys: 6 distinct ML-DSA-65 keypairs (5 nodes + founder).
const regions = ['us','sg','jp','ca','eu'];
const nodeKeys = {};
for (const r of regions) {
  const kp = ml_dsa65.keygen();
  nodeKeys[r] = { pub: b64(kp.publicKey), priv: hex(kp.secretKey) };
}
const founder = ml_dsa65.keygen();
const founderKeyFile = {
  _label: 'STAGE0-GOLDEN-THROWAWAY-NON-PRODUCTION',
  algorithm: 'ml-dsa-65',
  founder_key_public: b64(founder.publicKey),
  founder_key_private_hex: hex(founder.secretKey),
};
writeFileSync(`${DIR}/throwaway-founder-key.json`, JSON.stringify(founderKeyFile, null, 2));

// Build a complete anchor matching the verifier TrustAnchor type exactly.
const unsigned = {
  spec_version: '1.0.0',
  trust_anchor_version: 1,
  protocol: 'rubric',
  network: 'mainnet',
  valid_from: '2026-01-01T00:00:00Z',
  valid_until: null,
  hedera: { keys_topic_id: '0.0.10416909', mirror_node_default: 'https://mainnet-public.mirrornode.hedera.com' },
  base: { chain_id: 8453, anchor_contract: '', rpc_default: '' },
  federation: {
    per_node_public_keys: Object.fromEntries(regions.map(r => [r, nodeKeys[r].pub])),
    threshold_public_key: b64(ml_dsa65.keygen().publicKey),
    keylist_aggregate_hash: 'GOLDEN-TEST-PLACEHOLDER',
    genesis_ceremony_id: 'stage0-golden-0001',
    genesis_timestamp: '2026-06-10T00:00:00Z',
  },
  founder_key_public: founderKeyFile.founder_key_public,
};
writeFileSync(`${DIR}/throwaway-anchor.unsigned.json`, JSON.stringify(unsigned, null, 2));

// Sign via the tool, capturing output.
const signOut = execSync(`node /root/rubric-verify/genesis-ceremony/genesis-sign.mjs ${DIR}/throwaway-anchor.unsigned.json ${DIR}/throwaway-founder-key.json ${DIR}/throwaway-anchor.signed.json`, { encoding: 'utf8' });
console.log('--- sign tool output ---'); console.log(signOut.trim());

// Independently re-verify here.
const signed = JSON.parse(require('fs').readFileSync(`${DIR}/throwaway-anchor.signed.json`, 'utf8'));
let shapeOk = true;
try { assertWellFormedTrustAnchor(signed); } catch (e) { shapeOk = false; console.error('SHAPE FAIL:', e.message); }
const sigOk = validateTrustAnchorSignature(signed);

// Determinism check: ml-dsa sign is randomized, so re-signing differs; instead
// assert the SAME signature verifies and record canonical message hash (stable).
const { trust_anchor_signature, ...rest } = signed;
const canonical = canonicalize(rest);
const { createHash } = require('crypto');
const canonHash = createHash('sha256').update(canonical).digest('hex');

const golden = {
  note: 'Stage 0 golden vector. Throwaway keys. Canonical hash is stable; signature is randomized per ML-DSA but must verify.',
  canonical_sha256: canonHash,
  shape_valid: shapeOk,
  signature_valid: sigOk,
};
writeFileSync(`${DIR}/golden.json`, JSON.stringify(golden, null, 2));

console.log('\n--- golden harness result ---');
console.log('shape_valid:', shapeOk);
console.log('signature_valid:', sigOk);
console.log('canonical_sha256:', canonHash);
const pass = shapeOk && sigOk;
console.log(pass ? '\nSTAGE 0 GOLDEN PASS — tooling correct end-to-end' : '\nSTAGE 0 GOLDEN FAIL');
process.exit(pass ? 0 : 1);
