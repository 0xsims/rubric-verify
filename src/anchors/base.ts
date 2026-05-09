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
 * Event ABI assumption:
 *   The spec mandates "decode the AnchorStored event log to extract aggregateRoot"
 *   but does not pin the event signature. We default to `AnchorStored(bytes32)`
 *   with `aggregateRoot` as a non-indexed parameter (i.e. in `data`). The
 *   `eventSignature` option allows callers to override if the deployed contract
 *   uses a different signature (e.g. with timestamp, indexed root).
 */

import { keccak256, hexEncode } from '../crypto.js';
import { AnchorFetchError } from '../errors.js';
import type { BaseAnchorEvent } from '../types.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_EVENT_SIGNATURE = 'AnchorStored(bytes32)';

interface FetchOptions {
  baseRpc: string;
  contractAddress: string;
  txHash: string;
  /**
   * Solidity event signature to match. Default: "AnchorStored(bytes32)".
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
 * Tries (in order):
 *   1. A non-indexed bytes32 layout: aggregateRoot is the first 32 bytes of
 *      the log's `data` field.
 *   2. An indexed bytes32 layout: aggregateRoot is `topics[1]`.
 *
 * Both layouts are common for `AnchorStored(bytes32)` depending on whether
 * the contract author marked the parameter `indexed`.
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

    // Layout 1: non-indexed bytes32 in data.
    if (log.data && log.data.length >= 2 + 64) {
      const dataHex = log.data.startsWith('0x') ? log.data.slice(2) : log.data;
      const root = dataHex.slice(0, 64);
      if (root.length === 64 && /^[0-9a-fA-F]{64}$/.test(root)) {
        return { aggregate_root: root.toLowerCase(), raw: log };
      }
    }

    // Layout 2: indexed bytes32 in topics[1].
    if (log.topics.length >= 2) {
      const t1 = log.topics[1] as string;
      const t1Hex = t1.startsWith('0x') ? t1.slice(2) : t1;
      if (t1Hex.length === 64 && /^[0-9a-fA-F]{64}$/.test(t1Hex)) {
        return { aggregate_root: t1Hex.toLowerCase(), raw: log };
      }
    }
  }

  return null;
}
