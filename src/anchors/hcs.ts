/**
 * Hedera Consensus Service (HCS) anchor confirmation per spec §10.1.
 *
 * The mirror node is queried for a transaction by tx_id; the response's
 * `message` field is base64-encoded and contains the JSON-serialized message
 * submitted to HCS at issuance time. The verifier extracts the
 * `payload_hash` field.
 *
 * Spec contract:
 *   - On error or transaction-not-found: caller MUST treat
 *     hcs_anchor_confirmed as false. We surface this by returning `null`.
 *   - On success: returns `{ payload_hash, raw }`.
 */

import { base64Decode } from '../crypto.js';
import { AnchorFetchError } from '../errors.js';
import type { HcsMessage } from '../types.js';

const DEFAULT_TIMEOUT_MS = 15_000;

interface FetchOptions {
  hederaMirror: string;
  txId: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Fetch and decode an HCS message by tx_id.
 *
 * @returns the decoded message, or `null` if not found / network error.
 *          (Per spec §10.1, errors map to `hcs_anchor_confirmed = false`.)
 *
 * Throws `AnchorFetchError` only on programmer error (e.g. invalid URL); all
 * "the network said no" cases return null so the caller can compute a verdict
 * without exception handling on the hot path.
 */
export async function fetchHcsMessage(opts: FetchOptions): Promise<HcsMessage | null> {
  const fetchFn = opts.fetchImpl ?? globalThis.fetch;
  if (!fetchFn) {
    throw new AnchorFetchError('no fetch implementation available');
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const url = buildMirrorUrl(opts.hederaMirror, opts.txId);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetchFn(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
  } catch {
    // Network error / timeout / DNS — caller treats as not confirmed.
    return null;
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    return null;
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return null;
  }

  return decodeMirrorResponse(body);
}

/**
 * Build the mirror node URL for a transaction lookup.
 *
 * Per spec §10.1: GET {mirror_node}/api/v1/transactions/{encodeURIComponent(tx_id)}
 *
 * The Hedera mirror API actually returns transaction metadata at
 * `/api/v1/transactions/{tx_id}` with a list of related transactions. The
 * message body itself for an HCS submit is found at the related topic message
 * endpoint when the tx is a CONSENSUSSUBMITMESSAGE. To keep this verifier spec-
 * conformant and robust against the mirror node returning the bare transaction,
 * we accept either shape in `decodeMirrorResponse`.
 */
function buildMirrorUrl(base: string, txId: string): string {
  const trimmed = base.replace(/\/+$/, '');
  return `${trimmed}/api/v1/transactions/${encodeURIComponent(txId)}`;
}

/**
 * Decode a mirror node response body into an HcsMessage.
 *
 * The Hedera mirror API returns `{ transactions: [{ ..., memo_base64: '...' }] }`
 * for `/api/v1/transactions/{id}`. For HCS message submissions, the message
 * body is fetched separately from `/api/v1/topics/{topic}/messages/{seq}` and
 * has `{ message: '<base64>' }`. We accept both shapes:
 *
 *   - Direct topic-message response: `{ message: '<base64>' }`
 *   - Transaction response with embedded topic message info
 *
 * The caller may also pre-fetch the topic message and pass `decodeMirrorResponse`
 * the parsed body directly.
 *
 * The decoded base64 bytes are parsed as JSON; the `payload_hash` field is
 * extracted (spec §10.1).
 */
function decodeMirrorResponse(body: unknown): HcsMessage | null {
  if (!body || typeof body !== 'object') return null;
  const obj = body as Record<string, unknown>;

  // Shape 1: direct topic message response.
  if (typeof obj['message'] === 'string') {
    return decodeHcsMessageBase64(obj['message'] as string, obj);
  }

  // Shape 2: transaction list. Look for the first entry with a memo_base64,
  // which by Rubric protocol convention contains the HCS message body for the
  // ConsensusSubmitMessage transaction.
  if (Array.isArray(obj['transactions']) && obj['transactions'].length > 0) {
    for (const tx of obj['transactions'] as Record<string, unknown>[]) {
      // The mirror node embeds the submitted message in `memo_base64` for
      // ConsensusSubmitMessage transactions, OR in `message` if the caller
      // fetched the topic message endpoint instead. We try both.
      const candidate =
        (typeof tx['message'] === 'string' && (tx['message'] as string)) ||
        (typeof tx['memo_base64'] === 'string' && (tx['memo_base64'] as string)) ||
        null;
      if (candidate) {
        const decoded = decodeHcsMessageBase64(candidate, tx);
        if (decoded) return decoded;
      }
    }
  }

  return null;
}

function decodeHcsMessageBase64(b64: string, raw: unknown): HcsMessage | null {
  let decoded: Uint8Array;
  try {
    decoded = base64Decode(b64);
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(decoded));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const ph = (parsed as Record<string, unknown>)['payload_hash'];
  if (typeof ph !== 'string' || ph.length === 0) return null;
  return { payload_hash: ph, raw };
}
