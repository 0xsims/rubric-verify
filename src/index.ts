/**
 * @rubric/verify — reference implementation of the Rubric Attestation
 * Verification Specification v1.0.0.
 *
 * Public API:
 *
 *   verify(opts)                       - top-level verification entry
 *   validateTrustAnchorSignature(ta)   - check trust anchor's Ed25519 signature
 *   selectTrustAnchor(anchors, time)   - pick anchor covering an issuance time
 *   canonicalize(value)                - RFC 8785 JCS canonicalization
 *   canonicalizeBytes(value)           - same, returning UTF-8 bytes
 *   verifyMerkleProof(...)             - low-level Merkle proof verification
 *
 * All types from `./types` are re-exported.
 *
 * For most callers, only `verify()` is needed.
 */

export { verify } from './verify.js';

export {
  validateTrustAnchorSignature,
  selectTrustAnchor,
  trustAnchorCoversTime,
  assertWellFormedTrustAnchor,
} from './trust-anchor.js';

export { canonicalize, canonicalizeBytes } from './canonical.js';

export { verifyMerkleProof, merkleLeaf, merkleInternal } from './merkle.js';

export {
  RubricVerifyError,
  VerificationInputError,
  AnchorFetchError,
  SpecConformanceError,
} from './errors.js';

export type {
  Attestation,
  AttestationType,
  AttestationBase,
  AttestationPayload,
  DirectAttestation,
  TieredAttestation,
  ThresholdAttestation,
  Anchors,
  HcsAnchor,
  BaseAnchor,
  NodeRegion,
  MerkleDirection,
  TrustAnchor,
  VerifyOptions,
  VerifyResult,
  VerifyDetails,
  AnchorAccess,
  HcsMessage,
  BaseAnchorEvent,
} from './types.js';

/** Specification version this implementation conforms to. */
export const SPEC_VERSION = '1.0.0';

/** Implementation version. */
export const VERSION = '1.0.0-rc.1';
