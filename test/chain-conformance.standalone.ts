/**
 * Chain conformance — normative vectors of Verify Spec v2.0 Appendix A.
 * Standalone: `npx tsx test/chain-conformance.standalone.ts` (no jest, no deps).
 * These vectors are pinned against the deployed production sealer (2026-08-07).
 * If this file fails, the verifier has drifted from the chain. Do not ship.
 */
import { createHash } from "node:crypto";
import {
  chainCanonicalize, chainLeafDigest, buildChainTree, chainFold,
  chainEpochRoot, chainSessionRoot,
} from "../src/chain-merkle.js";
import { verifySessionProof, verifyEventChain, verifyAnchorPayload } from "../src/session-verify.js";

let fail = 0;
const ck = (l: string, got: unknown, want: unknown) => {
  const ok = got === want || got === true && want === true;
  if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${l}${ok ? "" : `\n      got  ${got}\n      want ${want}`}`);
};

// A.1 tiered inner roots (AGENT_OUTPUT)
const A1: Record<number, string> = {
  1: "d84ecda9fe4388e9e7dd94f9aef78d5763d5269268f30f0f527970be56204cb8",
  2: "f14c93e239c7372eb7357edfdbac03053ea018cc000043f26decd62d86636e29",
  3: "b17df03177e3b101bd8165c9b4b8af714ad4266f708833e5274bd355aecc83a0",
  5: "68739317569906c998868377d452c59755a6b97850a985d5ee9726ebd704d706",
};
for (const n of [1, 2, 3, 5]) {
  const ds = Array.from({ length: n }, (_, i) => chainLeafDigest("AGENT_OUTPUT", { a: i + 1 }));
  ck(`A.1 tiered inner n=${n}`, buildChainTree(ds).root, A1[n]);
}

// A.2 tiered session composition
{
  const eA = chainEpochRoot([0, 1, 2].map((i) => chainLeafDigest("AGENT_OUTPUT", { seq: i })));
  const eB = chainEpochRoot([3, 4].map((i) => chainLeafDigest("AGENT_OUTPUT", { seq: i })));
  ck("A.2 tiered session root", chainSessionRoot([{ root: eA, itemCount: 3 }, { root: eB, itemCount: 2 }]),
    "4de3a2da7694f6ba931cded3f31b4a4dbc2dbc5f59738fd0955704e06cbf2a52");
}

// A.3 SESSION_EVENT inner roots
const A3: Record<number, string> = {
  1: "b965e02e0acb0d7c26deec78d369e0d769f07ab38c543e1dccd4fb2884e5cb4a",
  2: "9165bbd3e10bde6ef547f657b4db75e031a4e79224e7ec3854605c93e1681955",
  3: "809c50b06aabf99968319c43f41f77bacb0bf8fa354eb57861e21971b65c7aa7",
  5: "a6c29d27a6c93e25c53358c3e7fbdf84966a648f2f83f1f335318cf974e6c420",
};
for (const n of [1, 2, 3, 5]) {
  const ds = Array.from({ length: n }, (_, i) => chainLeafDigest("SESSION_EVENT", { a: i + 1 }));
  ck(`A.3 session-event inner n=${n}`, buildChainTree(ds).root, A3[n]);
}

// A.4 SESSION_EVENT session composition
{
  const eA = chainEpochRoot([0, 1, 2].map((i) => chainLeafDigest("SESSION_EVENT", { seq: i })));
  const eB = chainEpochRoot([3, 4].map((i) => chainLeafDigest("SESSION_EVENT", { seq: i })));
  ck("A.4 session composition", chainSessionRoot([{ root: eA, itemCount: 3 }, { root: eB, itemCount: 2 }]),
    "7a09d2733bd8f6a62090730b9d4ca018ed038c29c105f1ac9fe282d05c9e108e");
}

// A.5 direct-family probe (SHA-256 over JCS — the OTHER family, for contrast)
ck("A.5 direct probe",
  createHash("sha256").update(chainCanonicalize({ family: "direct", msg: "rubric-conformance-probe", n: 1 })).digest("hex"),
  "63ae2efcc629818de7a338d1d98dbd41d7abfa08aa76436a99a0e200ba862f2b");

// A.6 live production proof (session sealed as HCS seq 2, topic 0.0.10800940)
{
  const p = {
    ses: "ses_9D4FC4A64CB540F2B5006E1A51", seq: 0,
    leaf: { v: 1, ses: "ses_9D4FC4A64CB540F2B5006E1A51", seq: 0, ts: "2026-08-07T21:46:58.783Z",
      kind: "note", actor: { agent_id: "agt_SMOKE", key_fp: "0".repeat(64) },
      body: null, body_digest: "1".repeat(64), prev: null },
    leaf_digest: "ec45cdf8b3c9449ce22a4bd0286d7a6ed03bf070e018d7fb8edf733da6102f07",
    leaf_path: [
      { hash: "0f80e0c7c46235aef368e16b780f90bd1d9f92d9c68d3747f2c5a8323b3d6bd4", position: "right" },
      { hash: "46c8009ab65882814923fc64298d0368fa154f2ba15af08b3c19b2fa50e57943", position: "right" },
      { hash: "378d6684e69343fa29e13556a57483e40c72720eeaddac4de4e28781a3137ffb", position: "right" },
      { hash: "dcfd35f87991fa1d5cafb550d7a5f700b10206928879e87f3113f30014bc2f67", position: "right" },
      { hash: "473f5d4a1bd8932ac2115af617c44d30d372abd46da1d33671cfc8afbe70947a", position: "right" },
    ],
    epoch_root: "9fd6628aeeddd7b0e7c125baeb0c9130a0b0caab864078e4a11b8acfba8d6cde",
    epoch_leaf_count: 20, epoch_index: 0, epoch_path: [],
    session_root: "f4f06e0a2349c70c1ef7d5e56c48f575f1b23836daa461432eefc5c4a24e222f",
  } as const;
  const r = verifySessionProof(p as any);
  ck("A.6 production proof (all checks)", r.ok, true);
  ck("A.6 anchor payload binds root",
    verifyAnchorPayload(p.session_root, { kind: "rsa-session-close", ses: p.ses, payload_hash: p.session_root }, p.ses).ok, true);
}

// chain-rule sanity: 3-event chain intact, then tampered
{
  const jcs = chainCanonicalize;
  const d = (o: unknown) => createHash("sha3-256").update(Buffer.from(jcs(o as any), "utf8")).digest("hex");
  const e0: any = { seq: 0, kind: "a", prev: null };
  const e1: any = { seq: 1, kind: "b", prev: d(e0) };
  const e2: any = { seq: 2, kind: "c", prev: d(e1) };
  ck("chain-rule intact", verifyEventChain([e0, e1, e2]).ok, true);
  const tampered = { ...e1, kind: "B" };
  ck("chain-rule detects tamper", verifyEventChain([e0, tampered, e2]).ok === false, true);
}

// proof soundness sweep
{
  let ok = true;
  for (let n = 1; n <= 16; n++) {
    const ds = Array.from({ length: n }, (_, i) => chainLeafDigest("SESSION_EVENT", { x: i }));
    const t = buildChainTree(ds);
    for (let i = 0; i < n; i++) if (chainFold(ds[i]!, t.proof(i)) !== t.root) ok = false;
  }
  ck("proof soundness n=1..16 all indices", ok, true);
}

console.log(fail === 0 ? "\nCHAIN-CONFORMANT — verifier reproduces all normative vectors." : `\n${fail} FAILURES — do not ship.`);
process.exit(fail ? 1 : 0);
