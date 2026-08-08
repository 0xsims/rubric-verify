/** Record retrieval. The verifier does not trust the source — every record's
 *  signature is checked against the anchored keys and every cross-reference
 *  against bound hashes — so ANY holder of the records can serve them: a
 *  federation node, a local directory of JSON files, or an adversary. */
import { readFileSync, existsSync } from "fs";
import { join } from "path";

const DEFAULT_NODES = [
  "https://rubric-protocol.com/verify",
];

export function makeLoader(opts: { dir?: string; nodes?: string[] }): (id: string) => Promise<any | null> {
  const nodes = opts.nodes ?? DEFAULT_NODES;
  const cache = new Map<string, any | null>();
  return async (id: string) => {
    if (cache.has(id)) return cache.get(id) ?? null;
    let rec: any | null = null;
    if (opts.dir) {
      const p = join(opts.dir, `${id}.json`);
      if (existsSync(p)) { try { rec = JSON.parse(readFileSync(p, "utf8")); } catch { rec = null; } }
    }
    if (!rec) {
      for (const base of nodes) {
        try {
          const r = await fetch(`${base}/v1/verify/${id}`, { signal: AbortSignal.timeout(8000) });
          if (!r.ok) continue;
          const j = await r.json() as any;
          // the verify route returns the record with verification metadata mixed in;
          // accept either the record itself or a wrapped {record} / {attestation}
          rec = j?.attestation ?? j?.record ?? (j?.attestation_id ? j : null);
          if (rec) break;
        } catch { /* try next node */ }
      }
    }
    cache.set(id, rec);
    return rec;
  };
}
