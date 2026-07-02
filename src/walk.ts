/** Provenance DAG walk, ported from the server's provenance-walk.ts.
 *  Verification of each node is injected (verify.ts + trust anchor). */
import type { TrustAnchor } from "./trust.js";
import { verifyRecord } from "./verify.js";

export interface TreeResult {
  verified: boolean;
  nodesVerified: number;
  spine: string[];
  evidenceLeaves: string[];
  externalLeaves: string[];
  unresolved: string[];
  reason?: string;
}

function normalizeParents(prov: any): any[] {
  if (!prov) return [];
  if (Array.isArray(prov.parents)) return prov.parents;
  if (typeof prov.parent_attestation_id === "string") return [prov];
  return [];
}

export async function verifyTree(
  start: any,
  loadById: (id: string) => Promise<any | null>,
  anchor: TrustAnchor,
  opts?: { maxNodes?: number; onNode?: (id: string, ok: boolean, note: string) => void },
): Promise<TreeResult> {
  const maxNodes = opts?.maxNodes ?? 4096;
  const seen = new Map<string, boolean>();
  const res: TreeResult = { verified: true, nodesVerified: 0, spine: [], evidenceLeaves: [], externalLeaves: [], unresolved: [] };
  let count = 0, failReason = "";

  const visit = async (node: any, onSpine: boolean): Promise<boolean> => {
    const id = node?.attestation_id;
    if (typeof id !== "string") { failReason = "record missing attestation_id"; return false; }
    if (seen.has(id)) return seen.get(id) === true;
    if (++count > maxNodes) { failReason = `max node count ${maxNodes} exceeded`; return false; }

    const r = verifyRecord(node, anchor);
    opts?.onNode?.(id, r.verified, r.reason);
    if (!r.verified) { seen.set(id, false); failReason = `node ${id} failed: ${r.reason}`; return false; }
    seen.set(id, true);
    res.nodesVerified += 1;
    if (onSpine) res.spine.push(id);

    for (const p of normalizeParents(node.provenance)) {
      const parent = await loadById(p.parent_attestation_id);
      if (!parent) { res.unresolved.push(p.parent_attestation_id); continue; }
      if (parent.payload_hash !== p.parent_payload_hash) {
        seen.set(id, false); failReason = `parent_payload_hash mismatch at ${p.parent_attestation_id}`; return false;
      }
      if (!(await visit(parent, true))) return false;
    }

    if (Array.isArray(node.evidence)) {
      for (const ev of node.evidence) {
        if (ev?.kind === "external") { res.externalLeaves.push(`${ev.provider}:${ev.role}`); continue; }
        if (ev?.kind === "attested") {
          const enode = await loadById(ev.attestation_id);
          if (!enode) { res.unresolved.push(ev.attestation_id); continue; }
          if (enode.payload_hash !== ev.payload_hash) {
            seen.set(id, false); failReason = `evidence payload_hash mismatch at ${ev.attestation_id}`; return false;
          }
          if (!(await visit(enode, false))) return false;
          res.evidenceLeaves.push(ev.attestation_id);
        }
      }
    }
    return true;
  };

  res.verified = await visit(start, true);
  if (!res.verified && failReason) res.reason = failReason;
  return res;
}
