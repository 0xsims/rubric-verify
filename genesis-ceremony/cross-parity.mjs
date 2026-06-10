// Stage 0 cross-parity: prove tempus canonicalize === verify-package canonicalize.
// If these diverge, what the federation signs and what the published verifier
// checks are different — silent genesis failure. Catch it here, on staging.
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const verifyMod = require('/root/rubric-verify/dist/cjs/index.js');
const verifyCanon = verifyMod.canonicalize;
const tempusMod = require('/root/tempus/dist/verify/canonical.js');
const tempusCanon = tempusMod.canonicalize;

const fixtures = [
  { a: 1, z: 2, m: 3 },
  { nested: { b: [3, 2, 1], a: null }, "": "empty-key", "üni": "code" },
  { num: 1e21, neg: -0, frac: 0.1, big: 12345678901234.5 },
  { arr: [{ k: 2 }, { k: 1 }], bool: true, nul: null },
  { unicode: "café\u00e9\ud83d\ude00", tab: "a\tb" },
];

let fail = 0;
for (const f of fixtures) {
  const v = verifyCanon(f);
  const t = tempusCanon(f);
  const ok = v === t;
  if (!ok) fail++;
  console.log(ok ? "MATCH" : "DIVERGE", JSON.stringify(f).slice(0, 50));
  if (!ok) { console.log("  verify:", v); console.log("  tempus:", t); }
}
console.log(fail === 0 ? "\nPARITY OK — all fixtures byte-identical" : `\nPARITY FAIL — ${fail} divergence(s)`);
process.exit(fail === 0 ? 0 : 1);
