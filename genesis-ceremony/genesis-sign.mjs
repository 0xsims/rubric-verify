// Genesis trust-anchor signer. Imports canonicalize from the published verify
// package so the bytes signed here are exactly the bytes the verifier checks.
// Signs over the anchor with trust_anchor_signature removed (matches
// validateTrustAnchorSignature: const {trust_anchor_signature, ...rest} = ta).
// ML-DSA-65 (FIPS 204). Usage:
//   node genesis-sign.mjs <unsigned-anchor.json> <founder-key.json> <out-signed.json>
import { createRequire } from 'module';
import { readFileSync, writeFileSync } from 'fs';
const require = createRequire(import.meta.url);
const { canonicalize } = require('/root/rubric-verify/dist/cjs/index.js');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa');

const [,, anchorPath, keyPath, outPath] = process.argv;
if (!anchorPath || !keyPath || !outPath) {
  console.error('usage: genesis-sign.mjs <unsigned-anchor.json> <founder-key.json> <out-signed.json>');
  process.exit(2);
}

const anchor = JSON.parse(readFileSync(anchorPath, 'utf8'));
const key = JSON.parse(readFileSync(keyPath, 'utf8'));

if (key.algorithm !== 'ml-dsa-65') {
  console.error(`REFUSE: founder key algorithm is "${key.algorithm}", expected "ml-dsa-65". Genesis must be post-quantum.`);
  process.exit(1);
}
const priv = Buffer.from(key.founder_key_private_hex, 'hex');
const pub = Buffer.from(key.founder_key_public, 'base64');

// Strip any existing signature; sign over the rest (verifier's exact contract).
const { trust_anchor_signature, ...rest } = anchor;
// Ensure founder_key_public in the anchor matches the signing key.
if (rest.founder_key_public !== key.founder_key_public) {
  console.error('REFUSE: anchor.founder_key_public does not match the signing key public.');
  process.exit(1);
}

const canonical = canonicalize(rest);
const msgBytes = new TextEncoder().encode(canonical);
const sig = ml_dsa65.sign(priv, msgBytes);
const sigHex = Buffer.from(sig).toString('hex');

// Self-check before writing: verify what we just produced.
const selfOk = ml_dsa65.verify(pub, msgBytes, sig);
if (!selfOk) {
  console.error('REFUSE: self-verification of produced signature FAILED. Not writing.');
  process.exit(1);
}

const signed = { ...rest, trust_anchor_signature: sigHex };
writeFileSync(outPath, JSON.stringify(signed, null, 2));
console.log('signed:', outPath);
console.log('sig bytes:', sig.length, '| sig hex len:', sigHex.length);
console.log('canonical preview:', canonical.slice(0, 80));
console.log('self-verify:', selfOk);
