/**
 * Base mainnet anchor confirmation per spec §10.2.
 *
 * Queries Base mainnet via JSON-RPC for `eth_getTransactionReceipt`, then
 * locates the `AnchorStored` event log emitted by the anchor contract and
 * extracts the `aggregateRoot` (bytes32).
 *
 * Spec contract:
 *   - On error or transaction-not-found: caller MUST treat
 *     base_anchor_confirmed as false. We surface this by returning `null`.
 *   - On success: returns `{ aggregate_root, raw }` (hex, no 0x prefix).
 *
 * Event signature (pinned, SP-2):
 *   The deployed anchor contract emits
 *     AnchorStored(uint256 indexed idx, bytes32 aggregateRoot,
 *                  string hederaTopicId, uint64 hcsSeqNum, uint64 itemCount)
 *   topic[0] = keccak256("AnchorStored(uint256,bytes32,string,uint64,uint64)")
 *            = 0x0afa64065fe05899b96e54651648f37828aeae87d448a675213c2564c5822958
 *   Only `idx` is indexed (topics[1]). `aggregateRoot` is the first
 *   non-indexed parameter, i.e. the first 32 bytes of `data`. Callers may
 *   override `eventSignature` for a different deployment.
 */

import { keccak256, hexEncode } from '../crypto.js';
import { AnchorFetchError } from '../errors.js';
import type { BaseAnchorEvent } from '../types.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_EVENT_SIGNATURE = 'AnchorStored(uint256,bytes32,string,uint64,uint64)';

interface FetchOptions {
  baseRpc: string;
  contractAddress: string;
  txHash: string;
  /**
   * Solidity event signature to match. Default:
   * "AnchorStored(uint256,bytes32,string,uint64,uint64)".
   * The selector (topic[0]) is computed as keccak256(eventSignature).
   */
  eventSignature?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Fetch a transaction receipt from Base and extract the `AnchorStored` event's
 * aggregateRoot.
 *
 * @returns the event payload, or `null` if the transaction is missing,
 *          the event is not found, or the network errors out.
 */
export async function fetchBaseAnchor(opts: FetchOptions): Promise<BaseAnchorEvent | null> {
  const fetchFn = opts.fetchImpl ?? globalThis.fetch;
  if (!fetchFn) {
    throw new AnchorFetchError('no fetch implementation available');
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const eventSig = opts.eventSignature ?? DEFAULT_EVENT_SIGNATURE;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetchFn(opts.baseRpc, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_getTransactionReceipt',
        params: [opts.txHash],
      }),
      signal: controller.signal,
    });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) return null;

  let body: { result?: TxReceipt; error?: unknown };
  try {
    body = (await response.json()) as { result?: TxReceipt; error?: unknown };
  } catch {
    return null;
  }
  if (body.error || !body.result) return null;

  return decodeAnchorStored(body.result, opts.contractAddress, eventSig);
}

/* -------------------------------------------------------------------------- */
/* JSON-RPC types                                                             */
/* -------------------------------------------------------------------------- */

interface TxReceipt {
  status?: string; // "0x1" success
  logs?: TxLog[];
}

interface TxLog {
  address?: string;
  topics?: string[];
  data?: string;
}

/* -------------------------------------------------------------------------- */
/* Event decoding                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Decode the AnchorStored event log from a transaction receipt.
 *
 * Layout (pinned, SP-2): only `idx` is indexed (topics[1]); `aggregateRoot`
 * is the first non-indexed parameter and therefore the first 32 bytes of the
 * log's `data`. We never read the root from topics[1] — that holds `idx`,
 * the monotonic counter. If a topic[0]-matching log has malformed data we
 * fail closed (return null) rather than guess.
 */
function decodeAnchorStored(
  receipt: TxReceipt,
  contractAddress: string,
  eventSignature: string,
): BaseAnchorEvent | null {
  if (receipt.status && receipt.status !== '0x1') return null;
  if (!receipt.logs || receipt.logs.length === 0) return null;

  const wantTopic =
    '0x' + hexEncode(keccak256(new TextEncoder().encode(eventSignature)));
  const wantAddrLower = contractAddress.toLowerCase();

  for (const log of receipt.logs) {
    if (!log.address || log.address.toLowerCase() !== wantAddrLower) continue;
    if (!log.topics || log.topics.length === 0) continue;
    if ((log.topics[0] as string).toLowerCase() !== wantTopic.toLowerCase()) continue;

    // aggregateRoot = first non-indexed parameter = first 32 bytes of data.
    if (log.data && log.data.length >= 2 + 64) {
      const dataHex = log.data.startsWith('0x') ? log.data.slice(2) : log.data;
      const root = dataHex.slice(0, 64);
      if (root.length === 64 && /^[0-9a-fA-F]{64}$/.test(root)) {
        return { aggregate_root: root.toLowerCase(), raw: log };
      }
    }
  }

  return null;
}
