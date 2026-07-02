#!/usr/bin/env node
/** rubric-verify <attestation-id> [--dir records/] [--trust-doc path|url] [--no-anchors] */
import { resolveTrustAnchor, readHcsMessage, TOPIC, COMMITMENT_SEQ } from "./trust.js";
import { verifyTree } from "./walk.js";
import { makeLoader } from "./fetch.js";

const args = process.argv.slice(2);
const id = args.find(a => !a.startsWith("--"));
const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const has = (n: string) => args.includes(n);

if (!id) { console.error("usage: rubric-verify <attestation-id> [--dir records/] [--trust-doc path|url] [--no-anchors]"); process.exit(2); }

const G = "\x1b[32m", Y = "\x1b[33m", R = "\x1b[31m", D = "\x1b[2m", X = "\x1b[0m", B = "\x1b[1m";

(async () => {
  console.log(`${D}rubric-verify · trust root: HCS topic ${TOPIC} seq ${COMMITMENT_SEQ} · no Rubric infrastructure trusted${X}\n`);

  // 1. trust anchor from the ledger
  const trust = await resolveTrustAnchor(flag("--trust-doc"));
  console.log(`${G}✓${X} trust anchor resolved — commitment on ledger ${trust.commitment.consensusTimestamp}, document hash verified`);
  console.log(`${D}  federation keys: ${Object.keys(trust.anchor.federation.per_node_public_keys).join(", ")}${X}\n`);

  // 2. load + walk
  const load = makeLoader({ dir: flag("--dir") });
  const start = await load(id);
  if (!start) { console.error(`${R}✕ cannot load attestation ${id}${X}`); process.exit(1); }
  const tree = await verifyTree(start, load, trust.anchor, {
    onNode: (nid, ok, note) => console.log(`${ok ? G + "✓" : R + "✕"}${X} ${nid.slice(0, 8)} ${D}${note}${X}`),
  });

  for (const u of tree.unresolved) console.log(`${Y}◌${X} ${u.slice(0, 8)} ${D}unresolved — not loadable, reported${X}`);
  for (const e of tree.externalLeaves) console.log(`${Y}◌${X} ${e} ${D}external source — disclosed, never vouched for${X}`);

  // 3. ledger anchors
  let anchorsOk: boolean | null = null;
  if (!has("--no-anchors")) {
    console.log(`\n${D}checking ledger anchors…${X}`);
    anchorsOk = true;
    const ids = [...new Set([...tree.spine, ...tree.evidenceLeaves])];
    for (const nid of ids) {
      const rec = await load(nid);
      const seq = rec?.anchors?.hcs?.sequence_number;
      if (!seq) { console.log(`${Y}◌${X} ${nid.slice(0, 8)} ${D}no anchor recorded${X}`); anchorsOk = false; continue; }
      const msg = await readHcsMessage(Number(seq));
      if (!msg) { console.log(`${Y}◌${X} ${nid.slice(0, 8)} ${D}mirror unavailable for seq ${seq}${X}`); anchorsOk = false; continue; }
      const okId = msg.json?.attestation_id === nid;
      const okPh = !rec.payload_hash || !msg.json?.payload_hash || msg.json.payload_hash === rec.payload_hash;
      if (okId && okPh) console.log(`${G}✓${X} ${nid.slice(0, 8)} ${D}anchored · ledger time ${msg.consensusTimestamp} · seq ${seq}${X}`);
      else { console.log(`${R}✕${X} ${nid.slice(0, 8)} ledger record at seq ${seq} does not match`); anchorsOk = false; }
    }
  }

  const pass = tree.verified && (anchorsOk !== false || has("--no-anchors"));
  console.log(`\n${B}${pass ? G + "THE RECORD HOLDS" : R + "NOT VERIFIED"}${X}`);
  console.log(`${D}${tree.nodesVerified} nodes verified · ${tree.externalLeaves.length} external disclosed · ${tree.unresolved.length} unresolved${tree.reason ? " · " + tree.reason : ""}${X}`);
  process.exit(pass ? 0 : 1);
})().catch(e => { console.error(`${R}✕ ${e?.message ?? e}${X}`); process.exit(1); });
