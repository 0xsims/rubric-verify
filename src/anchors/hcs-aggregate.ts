/**
 * Fetch a tier-2 aggregate anchor by sequence number.
 *
 * A tiered attestation does not appear on HCS individually — it is Merkle
 * batched, and what reaches the topic is an aggregate envelope carrying
 * aggregateRoot and tier1Count. The record's anchors.hcs.tx_id is empty, so
 * the tx-id based fetch used for direct attestations cannot locate it; the
 * sequence number is the only handle.
 */
import { AnchorFetchError } from '../errors.js';

const DEFAULT_TIMEOUT_MS = 10_000;

export interface AggregateAnchor {
  aggregateRoot: string;
  tier1Count: number;
  totalItems?: number;
  treeVersion?: number;
  raw: Record<string, unknown>;
}

export async function fetchHcsAggregate(opts: {
  hederaMirror: string;
  topicId: string;
  sequenceNumber: number;
  fetchImpl?: typeof globalThis.fetch;
  timeoutMs?: number;
}): Promise<AggregateAnchor | null> {
  const fetchFn = opts.fetchImpl ?? globalThis.fetch;
  if (!fetchFn) throw new AnchorFetchError('no fetch implementation available');
  if (!/^\d+\.\d+\.\d+$/.test(opts.topicId)) return null;
  if (!Number.isInteger(opts.sequenceNumber) || opts.sequenceNumber <= 0) return null;

  const url =
    `${opts.hederaMirror.replace(/\/+$/, '')}/api/v1/topics/${opts.topicId}` +
    `/messages?sequencenumber=${opts.sequenceNumber}&limit=1`;

  let body: any;
  try {
    const res = await fetchFn(url, {
      signal: AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    body = await res.json();
  } catch {
    return null;
  }

  const msg = Array.isArray(body?.messages) ? body.messages[0] : null;
  if (!msg || typeof msg.message !== 'string') return null;

  // Aggregate anchors are single-chunk by design (918 bytes in full form).
  // A chunked one cannot be reassembled from a sequence number alone.
  const total = msg.chunk_info?.total ?? 1;
  if (total !== 1) return null;

  let env: any;
  try {
    env = JSON.parse(Buffer.from(msg.message, 'base64').toString('utf8'));
  } catch {
    return null;
  }
  if (!env || typeof env !== 'object') return null;
  if (typeof env.aggregateRoot !== 'string') return null;

  return {
    aggregateRoot: env.aggregateRoot,
    tier1Count: typeof env.tier1Count === 'number' ? env.tier1Count : -1,
    totalItems: typeof env.totalItems === 'number' ? env.totalItems : undefined,
    treeVersion: typeof env.treeVersion === 'number' ? env.treeVersion : undefined,
    raw: env,
  };
}
