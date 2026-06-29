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
export type AttestationType = 'direct' | 'tiered' | 'threshold' | 'threshold-multisig';

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
/**
 * Provenance edge per spec §3.4. One entry per parent this attestation consumed.
 * Signed as a sibling of `payload`, so links are tamper-evident and
 * verifier-traversable (verify-chain walks the DAG these edges form).
 */
export interface ParentRef {
  parent_attestation_id: string;
  parent_payload_hash: string;
  parent_issuer_region: NodeRegion;
  relationship: 'consumed_output' | 'derived_from' | 'aggregated_from';
}

/**
 * DAG provenance: an attestation may have multiple parents (a merge) or none
 * (a root). Linear chains are the degenerate single-element case. Legacy
 * single-parent records ({parent_attestation_id,...}) are normalized at read
 * time by getParents() in verify-chain.ts and remain verifiable.
 */
export interface AttestationProvenance {
  parents: ParentRef[];
}

/**
 * Evidence reference per spec §5.5. Either an attested Rubric node (verifiable
 * by recursion) or an external source (recorded by hash; never silently treated
 * as verified). Signed as a sibling of `payload` when present.
 */
export type EvidenceRef =
  | {
      kind: 'attested';
      attestation_id: string;
      payload_hash: string;
      issuer_region: NodeRegion;
      role: string;
    }
  | {
      kind: 'external';
      source_type: 'database' | 'api' | 'file' | 'user_input' | 'sensor' | 'model_output' | 'blockchain';
      source_hash: string;
      provider: string;
      role: string;
    };

export interface AttestationBase {
  rubric_version: string;
  attestation_type: AttestationType;
  attestation_id: string;
  issuer_node_region: NodeRegion;
  issued_at: string;
  payload: AttestationPayload;
  /** Optional provenance link (spec §5.4); signed sibling of payload when present. */
  provenance?: AttestationProvenance;
  /** Optional evidence references (spec §5.5); signed sibling of payload when present. */
  evidence?: EvidenceRef[];
  /**
   * Algorithm suite this attestation was signed under (mirrors Proof-side
   * rubricAlgorithmSuite / CURRENT_ALGORITHM_SUITE). MUST equal the selected
   * trust anchor's suite_id. Optional for backward compat: a record emitted
   * before suite binding is treated as suite 1 (ML-DSA-65), the only suite
   * that has ever existed. NOTE: this default is safe ONLY while suite 1 is
   * the strongest suite. When suite 2 ships, the consensus-time cross-check
   * (Layer 2) MUST be in place to block forged-issued_at downgrade attacks.
   */
  suite_id?: number;
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
export interface QuorumDescriptor {
  policy: 'M-of-N';
  m: number;
  n: number;
  signer_regions: string[];
}

export interface NodeSignature {
  region: string;
  publicKey: string;
  signature: string;
}

export interface ThresholdMultisigAttestation {
  rubric_version: string;
  attestation_type: 'threshold-multisig';
  attestation_id: string;
  issuer_node_region: NodeRegion;
  issued_at: string;
  payload: AttestationPayload;
  provenance?: AttestationProvenance;
  evidence?: EvidenceRef[];
  suite_id?: number;
  quorum: QuorumDescriptor;
  signatures: NodeSignature[];
  anchors: Anchors;
}

export type Attestation = DirectAttestation | TieredAttestation | ThresholdAttestation | ThresholdMultisigAttestation;

/**
 * Trust anchor: hash-pinned, founder-signed bundle of federation parameters per spec §8.
 */
export interface TrustAnchor {
  spec_version: string;
  trust_anchor_version: number;
  protocol: 'rubric';
  network: 'mainnet' | 'testnet' | string;
  /**
   * Algorithm suite bound to this anchor epoch (see crypto.ts SUITE_* and
   * Proof-side CURRENT_ALGORITHM_SUITE). An attestation selected against this
   * anchor MUST declare the same suite; a mismatch fails verification.
   * Optional for backward compat with pre-suite-binding anchors (treated as 1).
   */
  suite_id?: number;
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
    /** M-of-N multi-signature quorum policy. */
    threshold_policy?: { m: number; n: number };
    keylist_aggregate_hash: string;
    genesis_ceremony_id: string;
    genesis_timestamp: string;
  };
  /** Base64-encoded ML-DSA-65 public key of the Rubric Founder Key. */
  founder_key_public: string;
  /** Hex-encoded ML-DSA-65 signature over the canonicalized trust anchor. */
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
  /** True if M-of-N quorum satisfied (threshold-multisig). */
  quorum_satisfied?: boolean;
  /** Recomputed canonical-message hash (threshold-multisig); cross-checked vs HCS. */
  expected_payload_hash?: string;
  /** True if the trust anchor signature itself was validated. */
  trust_anchor_signature_valid?: boolean;
  /** True if the trust anchor's [valid_from, valid_until] window covers `issued_at`. */
  trust_anchor_temporally_applicable?: boolean;
  /** True if the attestation's algorithm suite matches the selected anchor's bound suite. */
  suite_matches_trust_anchor?: boolean;
  /** True if the LEDGER consensus timestamp falls within the selected anchor's window (suite downgrade defense). */
  consensus_time_within_anchor?: boolean;
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
  /** Ledger-attested max consensus timestamp across the record's chunks (RFC seconds.nanos). Null if unavailable. */
  consensus_timestamp?: string | null;
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
