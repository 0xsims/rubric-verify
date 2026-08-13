/**
 * The exact object the producer hashes (spec §6.3), rebuilt from a record.
 *
 * Optional siblings are included ONLY when present — omitted, never null,
 * mirroring buildTieredLeafMessage in the producer.
 *
 * Every optional key the producer can add MUST appear here. A key the producer
 * hashes and this function omits yields a different leaf, and the record then
 * fails to verify against its own batch_root while looking, from the outside,
 * like a forgery. client_attestation is the key that made this necessary: it is
 * present on every record whose submitter signed locally, and it was missing
 * from both this verifier and the published constructions document until
 * 2026-08-13.
 *
 * Note the producer only includes client_attestation when the client signature
 * VERIFIED at ingest; an unverified one stays on the stub and never enters the
 * leaf. Records therefore either carry a verified block or none at all.
 */
import type { AttestationBase } from './types.js';

export function buildAttestationMessage(a: AttestationBase): Record<string, unknown> {
  return {
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
    ...(a.provenance ? { provenance: a.provenance } : {}),
    ...(a.evidence ? { evidence: a.evidence } : {}),
    ...(a.model_ref ? { model_ref: a.model_ref } : {}),
    ...(a.compliance_ref ? { compliance_ref: a.compliance_ref } : {}),
    ...(a.client_attestation ? { client_attestation: a.client_attestation } : {}),
  };
}
