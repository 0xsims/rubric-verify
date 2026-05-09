/**
 * Type definitions for the Rubric Attestation Verification Specification v1.0.0.
 *
 * Spec sections:
 *   §5 Attestation Record Format
 *   §8 Trust Anchor Format
 *   §9 Verification Algorithm (result types)
 */

/** Federation node region identifier per spec §5.1. */
export type NodeRegion = 'us' | 'sg' | 'jp' | 'ca' | 'eu';

/** Attestation type discriminator per spec §5.1. */
export type AttestationType = 'direct' | 'tiered' | 'threshold';

/** Merkle proof step direction per spec §7.4. */
export type MerkleDirection = 'L' | 'R';

/**
 * HCS (Hedera Consensus Service) anchor metadata per spec §5.1.
 */
export interface HcsAnchor {
  /** Hedera topic ID, e.g. "0.0.10416909". */
  topic_id: string;
  /** Hedera transaction ID. */
  tx_id: string;
  /** Hedera consensus timestamp. */
  consensus_timestamp: string;
  /** HCS sequence number for the message. */
  sequence_number: number;
}

/**
 * Base mainnet anchor metadata per spec §5.1.
 */
export interface BaseAnchor {
  /** Anchor contract address on Base mainnet. */
  contract_address: string;
  /** 0x-prefixed transaction hash. */
  tx_hash: string;
  /** Base block number. */
  block_number: number;
  /** Block timestamp in RFC 3339 UTC. */
  block_timestamp: string;
}

/** Anchor metadata bundle. */
export interface Anchors {
  hcs: HcsAnchor;
  base: BaseAnchor;
}

/**
 * Attestation payload — opaque customer-provided JSON value.
 * The verifier never inspects payload semantics.
 */
export type AttestationPayload = unknown;

/** Common fields present on every attestation type per spec §5.1. */
export interface AttestationBase {
  rubric_version: string;
  attestation_type: AttestationType;
  attestation_id: string;
  issuer_node_region: NodeRegion;
  issued_at: string;
  payload: AttestationPayload;
  /** Base64-encoded ML-DSA-65 public key (1952 bytes). */
  publicKey: string;
  /** Hex-encoded ML-DSA-65 signature (3293 bytes). */
  signature: string;
  anchors: Anchors;
}

/** Direct attestation (signed by a single per-node ML-DSA-65 key). */
export interface DirectAttestation extends AttestationBase {
  attestation_type: 'direct';
}

/** Tiered attestation: leaf in a Merkle batch whose root is signed (spec §5.2). */
export interface TieredAttestation extends AttestationBase {
  attestation_type: 'tiered';
  /** Hex-encoded sibling hashes, ordered from leaf to root. */
  merkle_proof: string[];
  /** Position of each sibling: "L" = sibling on left, "R" = sibling on right. */
  merkle_proof_directions: MerkleDirection[];
  /** Hex-encoded Merkle root (the value signed by `signature`). */
  batch_root: string;
  /** Number of attestations in the batch (informational). */
  batch_size: number;
}

/** Threshold attestation: signed by federation 3-of-5 threshold-aggregated key (spec §5.3). */
export interface ThresholdAttestation extends AttestationBase {
  attestation_type: 'threshold';
  /** Base64-encoded threshold-aggregated public key. */
  threshold_public_key: string;
  /** Indices (length 3) of contributing nodes; informational. */
  contributing_node_indices: number[];
  /** Hash of the federation KeyList aggregate at signing time. */
  threshold_keylist_hash: string;
}

/** Discriminated union of all attestation forms. */
export type Attestation = DirectAttestation | TieredAttestation | ThresholdAttestation;

/**
 * Trust anchor: hash-pinned, founder-signed bundle of federation parameters per spec §8.
 */
export interface TrustAnchor {
  spec_version: string;
  trust_anchor_version: number;
  protocol: 'rubric';
  network: 'mainnet' | 'testnet' | string;
  valid_from: string;
  /** Null if still current. */
  valid_until: string | null;
  hedera: {
    keys_topic_id: string;
    mirror_node_default: string;
  };
  base: {
    chain_id: number;
    anchor_contract: string;
    rpc_default: string;
  };
  federation: {
    per_node_public_keys: Record<NodeRegion, string>;
    threshold_public_key: string;
    keylist_aggregate_hash: string;
    genesis_ceremony_id: string;
    genesis_timestamp: string;
  };
  /** Base64-encoded Ed25519 public key of the Rubric Founder Key. */
  founder_key_public: string;
  /** Hex-encoded Ed25519 signature over the canonicalized trust anchor. */
  trust_anchor_signature: string;
}

/**
 * Per-attestation verification details (non-normative diagnostic surface).
 */
export interface VerifyDetails {
  signature_valid?: boolean;
  public_key_matches_trust_anchor?: boolean;
  hcs_anchor_confirmed?: boolean;
  base_anchor_confirmed?: boolean;
  anchor_roots_match?: boolean;
  merkle_proof_valid?: boolean;
  threshold_keylist_hash_matches?: boolean;
  /** True if the trust anchor signature itself was validated. */
  trust_anchor_signature_valid?: boolean;
  /** True if the trust anchor's [valid_from, valid_until] window covers `issued_at`. */
  trust_anchor_temporally_applicable?: boolean;
}

/** Top-level verification result per spec §9. */
export interface VerifyResult {
  /** Overall verdict: true iff all required cryptographic checks pass and anchors agree. */
  verified: boolean;
  /** Echoed from `attestation.attestation_id` for trace correlation. */
  attestation_id: string;
  /** Diagnostic details. Non-normative. */
  details: VerifyDetails;
  /** Human-readable failure reasons. Empty iff `verified === true`. */
  failures: string[];
}

/**
 * Network access policy controlling whether anchor confirmation is performed
 * over the network or supplied by the caller (e.g. for offline verification).
 */
export interface AnchorAccess {
  /**
   * Hedera mirror node base URL (e.g. https://mainnet-public.mirrornode.hedera.com).
   * If omitted, falls back to the trust anchor's `hedera.mirror_node_default`.
   */
  hederaMirror?: string;
  /**
   * Base mainnet JSON-RPC URL (e.g. https://mainnet.base.org).
   * If omitted, falls back to the trust anchor's `base.rpc_default`.
   */
  baseRpc?: string;
  /**
   * If true, MAY accept single-anchor confirmation when the other anchor returns
   * a network/RPC error (spec §10.3). Default: true.
   */
  allowSingleAnchor?: boolean;
  /**
   * Custom fetch implementation. Defaults to `globalThis.fetch`.
   * Useful for testing, proxies, or environments where fetch is unavailable.
   */
  fetch?: typeof fetch;
  /**
   * Per-request timeout in milliseconds for anchor fetches. Default: 15000.
   */
  timeoutMs?: number;
}

/** Input to the top-level verify function. */
export interface VerifyOptions {
  /** The attestation to verify. */
  attestation: Attestation;
  /**
   * Trust anchor(s). May be a single current anchor or a history (spec §8.3).
   * If multiple are supplied, the verifier selects the one whose
   * [valid_from, valid_until] window contains `attestation.issued_at`.
   */
  trustAnchor: TrustAnchor | TrustAnchor[];
  /** Network access policy. */
  access?: AnchorAccess;
}

/**
 * Raw result of fetching an HCS message for a given transaction ID.
 * The `payload_hash` field is extracted from the parsed message body
 * (spec §10.1).
 */
export interface HcsMessage {
  payload_hash: string;
  /** Echoed from the mirror node's response, useful for diagnostics. */
  raw?: unknown;
}

/**
 * Raw result of fetching the Base AnchorStored event for a given tx hash.
 * The `aggregate_root` field is the hex-encoded bytes32 from the event
 * (spec §10.2).
 */
export interface BaseAnchorEvent {
  aggregate_root: string;
  /** Echoed from the RPC, useful for diagnostics. */
  raw?: unknown;
}
