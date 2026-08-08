/** Root of trust for offline verification.
 *
 *  The ONLY constants baked into this package are:
 *    - the Hedera topic and operator account
 *    - the sequence number of the trust-anchor COMMITMENT attestation
 *  Everything else (federation public keys) derives from the ledger:
 *    1. Fetch the commitment message at COMMITMENT_SEQ from a public mirror
 *       node (chunk-aware: concurrent messages interleave in both directions
 *       and each chunk is independently base64-encoded).
 *    2. Require the paying account to be the Rubric operator account —
 *       only that account can write to the topic.
 *    3. The commitment carries sha3_256 of the trust-anchor document's exact
 *       bytes. Fetch the document (from the committed URL, a local file, or
 *       any mirror of it — the source does not matter), hash, compare.
 *    4. Select the anchor version valid for the verification time.
 */
import { createHash } from "crypto";
import { readFileSync } from "fs";

export const TOPIC = "0.0.10416909";
export const OPERATOR_ACCOUNT = "0.0.3923341";
export const COMMITMENT_SEQ = 276123;
const MIRRORS = [
  "https://mainnet.mirrornode.hedera.com/api/v1/topics",
  "https://mainnet-public.mirrornode.hedera.com/api/v1/topics",
];

async function mirrorGet(path: string): Promise<any | null> {
  for (const base of MIRRORS) {
    try {
      const r = await fetch(`${base}/${TOPIC}/${path}`, { signal: AbortSignal.timeout(8000) });
      if (r.ok) return r.json();
    } catch { /* try next mirror */ }
  }
  return null;
}

/** Chunk-aware HCS message read. Returns parsed JSON + ledger metadata. */
export async function readHcsMessage(seq: number): Promise<{ json: any; consensusTimestamp: string; payerAccount: string } | null> {
  const first = await mirrorGet(`messages/${seq}`);
  if (!first) return null;
  const total = first.chunk_info?.total ?? 1;
  const key = JSON.stringify(first.chunk_info?.initial_transaction_id ?? null);
  const payer = first.chunk_info?.initial_transaction_id?.account_id ?? first.payer_account_id ?? "";
  const parts = new Map<number, Buffer>();
  parts.set(first.chunk_info?.number ?? 1, Buffer.from(first.message ?? "", "base64"));
  if (total > 1) {
    let cursor = Math.max(1, seq - 25);
    for (let page = 0; page < 8 && parts.size < total; page++) {
      const batch = await mirrorGet(`messages?sequencenumber=gte:${cursor}&limit=100&order=asc`);
      if (!batch?.messages?.length) break;
      for (const m of batch.messages) {
        if (JSON.stringify(m.chunk_info?.initial_transaction_id ?? null) === key) {
          parts.set(m.chunk_info?.number ?? 0, Buffer.from(m.message ?? "", "base64"));
          if (parts.size >= total) break;
        }
      }
      cursor = (batch.messages[batch.messages.length - 1]?.sequence_number ?? cursor) + 1;
    }
  }
  if (parts.size < total) return null;
  const buf = Buffer.concat([...parts.entries()].sort((a, b) => a[0] - b[0]).map(e => e[1]));
  try {
    const json = JSON.parse(buf.toString("utf8"));
    const [s, n] = String(first.consensus_timestamp).split(".");
    const iso = new Date(parseInt(s) * 1000).toISOString().replace(".000Z", "." + (n ?? "0").slice(0, 3) + "Z");
    return { json, consensusTimestamp: iso, payerAccount: payer };
  } catch { return null; }
}

export interface TrustAnchor {
  federation: { per_node_public_keys: Record<string, string> };
  founder_key_public?: string;
  valid_from?: string;
  valid_until?: string;
  trust_anchor_version?: string;
  [k: string]: unknown;
}

export interface ResolvedTrust {
  anchor: TrustAnchor;
  commitment: { sha3_256: string; consensusTimestamp: string; seq: number };
  documentSource: string;
}

/** Resolve the trust anchor. `docOverride` may be a local file path or URL —
 *  the hash commitment makes the source irrelevant. */
export async function resolveTrustAnchor(docOverride?: string, at: Date = new Date()): Promise<ResolvedTrust> {
  const msg = await readHcsMessage(COMMITMENT_SEQ);
  if (!msg) throw new Error(`cannot read trust-anchor commitment at topic ${TOPIC} seq ${COMMITMENT_SEQ} from any mirror`);
  if (msg.payerAccount !== OPERATOR_ACCOUNT) {
    throw new Error(`commitment payer ${msg.payerAccount} is not the Rubric operator account ${OPERATOR_ACCOUNT}`);
  }
  const committedHash: string | undefined = msg.json?.payload?.sha3_256;
  const committedUrl: string | undefined = msg.json?.payload?.document_url;
  if (!committedHash || committedHash.length !== 64) throw new Error("commitment attestation carries no valid sha3_256");

  const source = docOverride ?? committedUrl;
  if (!source) throw new Error("no trust-anchor document source (commitment has no URL; pass --trust-doc)");
  let bytes: Buffer;
  if (/^https?:\/\//.test(source)) {
    const r = await fetch(source, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error(`trust-anchor document fetch failed: HTTP ${r.status} from ${source}`);
    bytes = Buffer.from(await r.arrayBuffer());
  } else {
    bytes = readFileSync(source);
  }
  const actual = createHash("sha3-256").update(bytes).digest("hex");
  if (actual !== committedHash) {
    throw new Error(`trust-anchor document hash mismatch:\n  on-chain commitment: ${committedHash}\n  fetched document:    ${actual}\nThe document has been altered or is the wrong version.`);
  }

  const doc = JSON.parse(bytes.toString("utf8"));
  const versions: TrustAnchor[] = Array.isArray(doc) ? doc : [doc];
  const now = at.getTime();
  const valid = versions.filter(v =>
    (!v.valid_from || Date.parse(v.valid_from) <= now) &&
    (!v.valid_until || Date.parse(v.valid_until) >= now));
  const anchor = (valid.length ? valid : versions).slice(-1)[0];
  if (!anchor?.federation?.per_node_public_keys) throw new Error("trust-anchor document has no federation keys");
  return { anchor, commitment: { sha3_256: committedHash, consensusTimestamp: msg.consensusTimestamp, seq: COMMITMENT_SEQ }, documentSource: source };
}
