/**
 * Top-level verification entry per Rubric Verify Spec v1.0.0 §9.1.
 *
 * Algorithm:
 *   1. Validate trust anchor signature (§9.2). If invalid, fail.
 *   2. Select trust anchor by temporal applicability (§8.3). If none, fail.
 *   3. Branch by attestation_type:
 *        - "direct"    -> verifyDirect    (§9.3)
 *        - "tiered"    -> verifyTiered    (§9.4)
 *        - "threshold" -> verifyThreshold (§9.5)
 *        - other       -> fail
 */

import {
  selectTrustAnchor,
  trustAnchorCoversTime,
  validateTrustAnchorSignature,
  assertWellFormedTrustAnchor,
} from './trust-anchor.js';
import { SUITE_ML_DSA_65 } from './crypto.js';
import { verifyDirect } from './verify-direct.js';
import { verifyTiered } from './verify-tiered.js';
import { verifyThreshold } from './verify-threshold.js';
import { verifyThresholdMultisig } from './verify-threshold-multisig.js';
import { VerificationInputError } from './errors.js';
import type {
  AnchorAccess,
  Attestation,
  TrustAnchor,
  VerifyOptions,
  VerifyResult,
} from './types.js';

const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Verify a Rubric attestation against a trust anchor (or trust anchor history).
 *
 * @returns a `VerifyResult` with the verdict and diagnostic details.
 *
 * Throws `VerificationInputError` only when the input cannot be coerced to a
 * verdict (e.g. missing required fields). Cryptographic failures, anchor
 * mismatches, and stale trust anchors all produce `verified: false` rather
 * than throwing.
 */
export async function verify(opts: VerifyOptions): Promise<VerifyResult> {
  assertWellFormedAttestation(opts.attestation);

  const trustAnchors = Array.isArray(opts.trustAnchor)
    ? opts.trustAnchor
    : [opts.trustAnchor];

  if (trustAnchors.length === 0) {
    throw new VerificationInputError('at least one trust anchor is required');
  }
  for (const ta of trustAnchors) {
    assertWellFormedTrustAnchor(ta);
  }

  const access = normalizeAccess(opts.access);
  const a = opts.attestation;

  /* §9.2 — Validate trust anchor signature(s) and pick one covering issued_at. */
  const candidates: TrustAnchor[] = [];
  let anySignatureValid = false;
  for (const ta of trustAnchors) {
    const sigOk = validateTrustAnchorSignature(ta);
    if (sigOk) {
      anySignatureValid = true;
      if (trustAnchorCoversTime(ta, a.issued_at)) candidates.push(ta);
    }
  }
  if (!anySignatureValid) {
    return failure(a.attestation_id, 'trust anchor signature invalid', {
      trust_anchor_signature_valid: false,
    });
  }

  const chosen = selectTrustAnchor(candidates, a.issued_at);
  if (!chosen) {
    return failure(
      a.attestation_id,
      `no trust anchor covers attestation issued_at=${a.issued_at}`,
      {
        trust_anchor_signature_valid: true,
        trust_anchor_temporally_applicable: false,
      },
    );
  }

  /* Suite binding: the attestation's algorithm suite MUST equal the selected
   * anchor's bound suite. Both default to ML-DSA-65 (suite 1) for records and
   * anchors emitted before suite binding existed. A mismatch is a hard fail —
   * a verifier MUST NOT accept a record signed under a suite the anchor for its
   * epoch did not authorize. */
  const recordSuite = a.suite_id ?? SUITE_ML_DSA_65;
  const anchorSuite = chosen.suite_id ?? SUITE_ML_DSA_65;
  if (recordSuite !== anchorSuite) {
    return failure(
      a.attestation_id,
      `algorithm suite mismatch: attestation=${recordSuite} anchor=${anchorSuite}`,
      {
        trust_anchor_signature_valid: true,
        trust_anchor_temporally_applicable: true,
        suite_matches_trust_anchor: false,
      },
    );
  }

  /* Network-endpoint fallback: if the caller supplied no mirror/RPC, inherit
   * the selected anchor's declared defaults so external default-access
   * verification works without hand-configuring endpoints. Applies to all
   * attestation types (the dispatch below). */
  if (!access.hederaMirror) access.hederaMirror = chosen.hedera?.mirror_node_default ?? '';
  if (!access.baseRpc) access.baseRpc = chosen.base?.rpc_default ?? '';

  /* §9.1 — Branch by attestation type. */
  const baseResult = await dispatchByType(a, chosen, access);

  // Stamp the trust-anchor diagnostic flags.
  baseResult.details.trust_anchor_signature_valid = true;
  baseResult.details.trust_anchor_temporally_applicable = true;
  baseResult.details.suite_matches_trust_anchor = true;
  return baseResult;
}

async function dispatchByType(
  a: Attestation,
  ta: TrustAnchor,
  access: Required<AnchorAccess>,
): Promise<VerifyResult> {
  switch (a.attestation_type) {
    case 'direct':
      return verifyDirect(a, ta, access);
    case 'tiered':
      return verifyTiered(a, ta, access);
    case 'threshold':
      return verifyThreshold(a, ta, access);
    case 'threshold-multisig':
      return verifyThresholdMultisig(a, ta, access);
    default:
      // Discriminated union exhaustiveness; runtime guard for non-TS callers.
      return failure(
        (a as Attestation).attestation_id,
        `unsupported attestation_type: ${String((a as Attestation).attestation_type)}`,
      );
  }
}

function failure(
  attestationId: string,
  message: string,
  details: VerifyResult['details'] = {},
): VerifyResult {
  return {
    verified: false,
    attestation_id: attestationId,
    details,
    failures: [message],
  };
}

function normalizeAccess(access: AnchorAccess | undefined): Required<AnchorAccess> {
  return {
    hederaMirror: access?.hederaMirror ?? '',
    baseRpc: access?.baseRpc ?? '',
    allowSingleAnchor: access?.allowSingleAnchor ?? true,
    fetch: access?.fetch ?? globalThis.fetch,
    timeoutMs: access?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
}

/**
 * Light structural validation. Shape-checks required string fields and the
 * anchors block; deeper validation occurs in the per-type verifiers.
 */
function assertWellFormedAttestation(a: unknown): asserts a is Attestation {
  if (!a || typeof a !== 'object') {
    throw new VerificationInputError('attestation must be an object');
  }
  const obj = a as Record<string, unknown>;
  const baseFields = [
    'rubric_version',
    'attestation_type',
    'attestation_id',
    'issuer_node_region',
    'issued_at',
  ];
  // threshold-multisig carries signatures[] instead of a single publicKey/signature.
  const isMultisig = obj['attestation_type'] === 'threshold-multisig';
  const requiredStrings = isMultisig ? baseFields : [...baseFields, 'publicKey', 'signature'];
  for (const k of requiredStrings) {
    if (typeof obj[k] !== 'string') {
      throw new VerificationInputError(`attestation: required string "${k}" missing/invalid`);
    }
  }
  if (!('payload' in obj)) {
    throw new VerificationInputError('attestation: payload missing');
  }
  if (!obj['anchors'] || typeof obj['anchors'] !== 'object') {
    throw new VerificationInputError('attestation: anchors missing');
  }
  if ('suite_id' in obj && typeof obj['suite_id'] !== 'number') {
    throw new VerificationInputError('attestation: suite_id must be a number when present');
  }
  const t = obj['attestation_type'];
  if (t !== 'direct' && t !== 'tiered' && t !== 'threshold' && t !== 'threshold-multisig') {
    throw new VerificationInputError(`attestation: unsupported type "${String(t)}"`);
  }
  if (t === 'threshold-multisig') {
    if (!Array.isArray(obj['signatures']) || (obj['signatures'] as unknown[]).length === 0) {
      throw new VerificationInputError('threshold-multisig attestation missing signatures[]');
    }
    if (!obj['quorum'] || typeof obj['quorum'] !== 'object') {
      throw new VerificationInputError('threshold-multisig attestation missing quorum');
    }
  }
  if (t === 'tiered') {
    if (!Array.isArray(obj['merkle_proof']) || !Array.isArray(obj['merkle_proof_directions'])) {
      throw new VerificationInputError('tiered attestation missing merkle_proof/directions');
    }
    if (typeof obj['batch_root'] !== 'string') {
      throw new VerificationInputError('tiered attestation missing batch_root');
    }
  }
  if (t === 'threshold') {
    if (typeof obj['threshold_keylist_hash'] !== 'string') {
      throw new VerificationInputError(
        'threshold attestation missing threshold_keylist_hash',
      );
    }
  }
}
