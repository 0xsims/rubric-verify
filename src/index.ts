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
export { verifyThresholdMultisig } from './verify-threshold-multisig.js';

export { verifyChain } from './verify-chain.js';
export type {
  ChainFinding,
  ChainVerifyResult,
  ChainVerifyOptions,
  StepVerifier,
  StepVerifyResult,
} from './verify-chain.js';

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
  ThresholdMultisigAttestation,
  QuorumDescriptor,
  NodeSignature,
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
export const SPEC_VERSION = '2.0.0';

/** Implementation version. */
export const VERSION = '2.0.0-rc.1';
export * from './spec-signature.js';

// rc2 §7.5-7.10/§9.7: the canonical on-chain construction and Session Attestation verification.
// These are the modules that reproduce real mainnet anchors (Verify Spec v1.0.0-rc2
// §4.7/§9); the SHA-256 paths above cover the direct/threshold family only.
export * from './chain-merkle.js';
export * from './session-verify.js';
export * from './session-signature.js';
