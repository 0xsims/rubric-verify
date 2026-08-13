/**
 * Decide which object to hash as this record's Merkle leaf.
 *
 * Prefer the record's own fields. Fall back to attestation.stub.leafMessage —
 * currently the only place /v1/verify/:id exposes the leaf's optional keys —
 * but only after proving the stub copy is about the same attestation:
 *
 *   * every key it carries is one the published spec allows in a leaf;
 *   * all six always-present keys are byte-identical to the record's;
 *   * otherwise the stub is refused and the record's own six keys are hashed,
 *     with the contradiction reported as a failure.
 *
 * The fallback is not a trust shortcut. The leaf still has to walk the Merkle
 * proof to batch_root, and batch_root still has to reconstruct to the anchored
 * aggregate root. All the stub can supply is optional-key CONTENT that was
 * anchored at flush time along with everything else; it cannot change what the
 * attestation is about.
 */
import type { AttestationBase } from './types.js';
import { buildAttestationMessage } from './canonical-message.js';

const ALWAYS = [
  'rubric_version',
  'attestation_type',
  'attestation_id',
  'issuer_node_region',
  'issued_at',
  'payload',
] as const;

const OPTIONAL = [
  'provenance',
  'evidence',
  'model_ref',
  'compliance_ref',
  'client_attestation',
] as const;

export interface LeafResolution {
  /** The object to canonicalize and hash. */
  message: Record<string, unknown>;
  /** Where the optional keys came from. */
  source: 'record' | 'stub';
  /** Set when the fallback was used, for surfacing to the caller. */
  note?: string;
  /** Set when the stub was refused; belongs in `failures`. */
  error?: string;
}

/** Order-insensitive structural equality, for comparison only — never hashed. */
function stable(v: unknown): string {
  if (v === undefined) return 'undefined';
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'undefined';
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stable(o[k])}`)
    .join(',')}}`;
}

export function resolveLeafMessage(a: AttestationBase): LeafResolution {
  const fromRecord = buildAttestationMessage(a);
  const rec = a as unknown as Record<string, unknown>;

  // The record carries its own optional keys — nothing to reconcile.
  if (OPTIONAL.some((k) => rec[k] !== undefined && rec[k] !== null)) {
    return { message: fromRecord, source: 'record' };
  }

  const stub = (a as { stub?: { leafMessage?: unknown } }).stub;
  const lm = stub?.leafMessage;
  if (!lm || typeof lm !== 'object' || Array.isArray(lm)) {
    return { message: fromRecord, source: 'record' };
  }

  const cand = lm as Record<string, unknown>;
  const allowed = new Set<string>([...ALWAYS, ...OPTIONAL]);
  const unexpected = Object.keys(cand).filter((k) => !allowed.has(k));
  const missing = ALWAYS.filter((k) => !(k in cand));
  if (unexpected.length > 0 || missing.length > 0) {
    return {
      message: fromRecord,
      source: 'record',
      error:
        'stub.leafMessage does not match the published leaf shape and was not used ' +
        `(unexpected keys: ${unexpected.join(', ') || 'none'}; ` +
        `missing required: ${missing.join(', ') || 'none'})`,
    };
  }

  const divergent = ALWAYS.filter((k) => stable(cand[k]) !== stable(fromRecord[k]));
  if (divergent.length > 0) {
    return {
      message: fromRecord,
      source: 'record',
      error:
        'stub.leafMessage contradicts the record on ' +
        `${divergent.join(', ')} — refusing to hash the server's copy`,
    };
  }

  const carried = OPTIONAL.filter((k) => k in cand);
  if (carried.length === 0) {
    return { message: fromRecord, source: 'record' };
  }

  return {
    message: cand,
    source: 'stub',
    note:
      `optional leaf keys (${carried.join(', ')}) were read from ` +
      'attestation.stub.leafMessage: this API response does not expose them at the ' +
      'top level of `attestation`. The six signed core fields were confirmed ' +
      'identical to the record before hashing.',
  };
}
