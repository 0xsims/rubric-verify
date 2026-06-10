// Genesis verifier. Uses the published package's own validateTrustAnchorSignature
// and assertWellFormedTrustAnchor — the exact code an external auditor runs.
// Usage: node genesis-verify.mjs <signed-anchor.json>
import { createRequire } from 'module';
import { readFileSync } from 'fs';
const require = createRequire(import.meta.url);
const v = require('/root/rubric-verify/dist/cjs/index.js');

const [,, anchorPath] = process.argv;
if (!anchorPath) { console.error('usage: genesis-verify.mjs <signed-anchor.json>'); process.exit(2); }
const anchor = JSON.parse(readFileSync(anchorPath, 'utf8'));

let shapeOk = true;
try { v.assertWellFormedTrustAnchor(anchor); }
catch (e) { shapeOk = false; console.error('SHAPE FAIL:', e.message); }

const sigOk = v.validateTrustAnchorSignature(anchor);

// Region completeness (the guard does NOT enforce this; genesis must have all 5).
const regions = ['us','sg','jp','ca','eu'];
const keys = anchor.federation?.per_node_public_keys || {};
const present = regions.filter(r => typeof keys[r] === 'string' && keys[r].length > 0);
const distinct = new Set(regions.map(r => keys[r]));
const allPresent = present.length === 5;
const allDistinct = distinct.size === 5;

console.log('shape_valid:', shapeOk);
console.log('signature_valid:', sigOk);
console.log('regions_present:', present.length + '/5', allPresent ? 'OK' : 'MISSING');
console.log('per_node_keys_distinct:', allDistinct ? 'OK (5 unique)' : `FAIL (${distinct.size} unique)`);
const pass = shapeOk && sigOk && allPresent && allDistinct;
console.log(pass ? '\nGENESIS VERIFY PASS' : '\nGENESIS VERIFY FAIL');
process.exit(pass ? 0 : 1);
