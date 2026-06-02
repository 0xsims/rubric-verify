/**
 * Hedera Consensus Service (HCS) anchor confirmation per spec §10.1.
 *
 * The Rubric publisher submits the attestation envelope via
 * TopicMessageSubmitTransaction with setMaxChunks(20). Envelopes larger than
 * the ~1024-byte HCS message limit are split into N chunks, each carrying
 * `chunk_info` with a shared `initial_transaction_id` and a 1-indexed
 * `number`/`total`. The record's `anchors.hcs.tx_id` equals that
 * initial_transaction_id (the SDK derives all chunk tx-ids from the first).
 *
 * Reassembly contract (verified against live topic 0.0.10416909):
 *   - Chunks do NOT arrive in chunk-number order; sequence_number and
 *     consensus_timestamp ordering can differ from chunk.number ordering.
 *     Reassembly MUST sort strictly by chunk_info.number.
 *   - All `total` chunks MUST be present; a gap => not confirmed.
 *   - The reassembled UTF-8 is the JSON envelope. We extract payload_hash and
 *     cross-check the four record fields (spec §10.1 steps 4-8).
 *
 * On any error / missing chunk / field mismatch we return `null`, which the
 * caller maps to hcs_anchor_confirmed = false (spec §10.1).
 */

import { base64Decode } from '../crypto.js';
import { AnchorFetchError } from '../errors.js';
import type { HcsMessage } from '../types.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_PAGES = 20;

/** Fields the verifier cross-checks the on-chain envelope against (spec §10.1). */
export interface HcsExpectedFields {
  attestation_id: string;
  attestation_type: string;
  issuer_node_region: string;
  issued_at: string;
}

interface FetchOptions {
  hederaMirror: string;
  /** anchors.hcs.topic_id, e.g. "0.0.10416909". */
  topicId: string;
  /** anchors.hcs.tx_id, e.g. "0.0.3923341@1779689395.030033472". */
  txId: string;
  /** Expected envelope fields for cross-reference validation (spec §10.1 steps 4-8). */
  expected: HcsExpectedFields;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

interface ParsedTxId {
  accountId: string;
  validStart: string; // "<seconds>.<nanos>"
}

/**
 * Parse a record tx_id ("0.0.x@<secs>.<nanos>") into the components the mirror
 * node reports inside chunk_info.initial_transaction_id.
 */
function parseTxId(txId: string): ParsedTxId | null {
  const at = txId.indexOf('@');
  if (at <= 0 || at === txId.length - 1) return null;
  const accountId = txId.slice(0, at);
  const validStart = txId.slice(at + 1);
  if (!/^\d+\.\d+\.\d+$/.test(accountId)) return null;
  if (!/^\d+\.\d+$/.test(validStart)) return null;
  return { accountId, validStart };
}

/**
 * Fetch, reassemble, and validate the HCS envelope for an attestation.
 *
 * @returns the decoded envelope (with payload_hash) or `null` on any failure.
 */
export async function fetchHcsMessage(opts: FetchOptions): Promise<HcsMessage | null> {
  const fetchFn = opts.fetchImpl ?? globalThis.fetch;
  if (!fetchFn) throw new AnchorFetchError('no fetch implementation available');
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const parsed = parseTxId(opts.txId);
  if (!parsed) return null;
  if (!/^\d+\.\d+\.\d+$/.test(opts.topicId)) return null;

  const base = opts.hederaMirror.replace(/\/+$/, '');
  // Bound the scan at the submission's valid_start (precedes all chunk
  // consensus timestamps), ascending, paging forward.
  let nextUrl: string | null =
    `${base}/api/v1/topics/${opts.topicId}/messages` +
    `?timestamp=gte:${encodeURIComponent(parsed.validStart)}&order=asc&limit=100`;

  const chunks = new Map<number, Uint8Array>();
  let expectedTotal = -1;

  for (let page = 0; page < MAX_PAGES && nextUrl; page++) {
    const body = await getJson(fetchFn, nextUrl, timeoutMs);
    if (!body) return null;
    const messages = (body as Record<string, unknown>)['messages'];
    if (!Array.isArray(messages)) return null;

    for (const m of messages as Record<string, unknown>[]) {
      const ci = m['chunk_info'] as Record<string, unknown> | undefined;

      // Unchunked submission: chunk_info absent. Match by the message's own
      // transaction id if present; otherwise skip (cannot attribute).
      if (!ci) continue;

      if (!matchesInitialTx(ci, parsed)) continue;
      const number = toInt(ci['number']);
      const total = toInt(ci['total']);
      if (number === null || total === null) return null;
      if (expectedTotal === -1) expectedTotal = total;
      else if (expectedTotal !== total) return null;
      const bytes = decodeB64(m['message']);
      if (!bytes) return null;
      chunks.set(number, bytes);
    }

    if (expectedTotal > 0 && chunks.size >= expectedTotal) break;

    const links = (body as Record<string, unknown>)['links'] as
      | { next?: string | null }
      | undefined;
    nextUrl = links?.next ? absolutize(base, links.next) : null;
  }

  if (expectedTotal <= 0 || chunks.size !== expectedTotal) return null;

  // Reassemble strictly by chunk number (NOT by seq / consensus_timestamp).
  const parts: Uint8Array[] = [];
  for (let i = 1; i <= expectedTotal; i++) {
    const c = chunks.get(i);
    if (!c) return null; // gap
    parts.push(c);
  }
  const totalLen = parts.reduce((n, p) => n + p.length, 0);
  const joined = new Uint8Array(totalLen);
  let off = 0;
  for (const p of parts) { joined.set(p, off); off += p.length; }

  let env: Record<string, unknown>;
  try {
    env = JSON.parse(new TextDecoder().decode(joined)) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!env || typeof env !== 'object') return null;

  // Spec §10.1 steps 4-8: cross-reference envelope against the record.
  if (env['attestation_id'] !== opts.expected.attestation_id) return null;
  if (env['attestation_type'] !== opts.expected.attestation_type) return null;
  if (env['issuer_node_region'] !== opts.expected.issuer_node_region) return null;
  if (env['issued_at'] !== opts.expected.issued_at) return null;

  const ph = env['payload_hash'];
  if (typeof ph !== 'string' || ph.length === 0) return null;

  return { payload_hash: ph, raw: env };
}

function matchesInitialTx(ci: Record<string, unknown>, parsed: ParsedTxId): boolean {
  const itx = ci['initial_transaction_id'] as Record<string, unknown> | undefined;
  if (!itx) return false;
  return (
    itx['account_id'] === parsed.accountId &&
    itx['transaction_valid_start'] === parsed.validStart
  );
}

function toInt(v: unknown): number | null {
  if (typeof v === 'number' && Number.isInteger(v)) return v;
  if (typeof v === 'string' && /^\d+$/.test(v)) return parseInt(v, 10);
  return null;
}

function decodeB64(v: unknown): Uint8Array | null {
  if (typeof v !== 'string') return null;
  try { return base64Decode(v); } catch { return null; }
}

async function getJson(
  fetchFn: typeof fetch,
  url: string,
  timeoutMs: number,
): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function absolutize(base: string, next: string): string {
  if (next.startsWith('http')) return next;
  const origin = base.replace(/\/api\/v1.*$/, '').replace(/\/+$/, '');
  return origin + (next.startsWith('/') ? next : '/' + next);
}
