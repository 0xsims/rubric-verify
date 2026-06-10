/**
 * End-to-end verification tests using self-generated keys and signatures.
 *
 * These tests exercise:
 *   - Successful direct, tiered, and threshold verification with a stubbed fetch
 *     returning matching anchors.
 *   - Tampered signature -> verified = false  (spec §14.1)
 *   - Tampered payload   -> verified = false  (spec §14.2)
 *   - Wrong public key   -> verified = false  (spec §14.3)
 *   - HCS-Base mismatch  -> verified = false  (spec §14.5)
 *   - Truncated signature -> verified = false (spec §14.8)
 *   - Trust anchor signature failure
 *
 * The §13/§14 federation-issued vectors are populated at spec ratification time.
 * These tests use locally generated keys to verify the implementation's logic.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';

import { canonicalize, canonicalizeBytes } from '../src/canonical.js';
import { sha256, hexEncode, base64Encode, keccak256 } from '../src/crypto.js';
import { merkleLeaf, merkleInternal } from '../src/merkle.js';
import { verify } from '../src/verify.js';
import type {
  Attestation,
  DirectAttestation,
  TieredAttestation,
  ThresholdAttestation,
  TrustAnchor,
} from '../src/types.js';

/* -------------------------------------------------------------------------- */
/* Fixture helpers                                                            */
/* -------------------------------------------------------------------------- */

const ANCHOR_CONTRACT = '0x' + 'ab'.repeat(20);
const HCS_TX_ID = '0.0.1234567@1714000000.000000000';
const BASE_TX_HASH = '0x' + '11'.repeat(32);

function genMlDsaKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const seed = randomBytes(32);
  const kp = ml_dsa65.keygen(seed);
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

function genEd25519KeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const sk = randomBytes(32);
  const pk = ed25519.getPublicKey(sk);
  return { publicKey: pk, secretKey: sk };
}

/** Sign a trust anchor: canonicalize without the signature field, ML-DSA-65-sign. */
function signTrustAnchor(ta: Omit<TrustAnchor, 'trust_anchor_signature'>, sk: Uint8Array): string {
  const c = canonicalize(ta);
  const msg = new TextEncoder().encode(c);
  const sig = ml_dsa65.sign(sk, msg);
  return hexEncode(sig);
}

interface Fixture {
  trustAnchor: TrustAnchor;
  perNodeKeys: Record<string, { publicKey: Uint8Array; secretKey: Uint8Array }>;
  thresholdKey: { publicKey: Uint8Array; secretKey: Uint8Array };
}

function buildFixture(): Fixture {
  const founderKp = genMlDsaKeyPair();
  const us = genMlDsaKeyPair();
  const sg = genMlDsaKeyPair();
  const jp = genMlDsaKeyPair();
  const ca = genMlDsaKeyPair();
  const eu = genMlDsaKeyPair();
  const threshold = genMlDsaKeyPair();

  const taBase: Omit<TrustAnchor, 'trust_anchor_signature'> = {
    spec_version: '1.0.0',
    trust_anchor_version: 1,
    protocol: 'rubric',
    network: 'mainnet',
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: null,
    hedera: {
      keys_topic_id: '0.0.10416909',
      mirror_node_default: 'https://mainnet-public.mirrornode.hedera.com',
    },
    base: {
      chain_id: 8453,
      anchor_contract: ANCHOR_CONTRACT,
      rpc_default: 'https://mainnet.base.org',
    },
    federation: {
      per_node_public_keys: {
        us: base64Encode(us.publicKey),
        sg: base64Encode(sg.publicKey),
        jp: base64Encode(jp.publicKey),
        ca: base64Encode(ca.publicKey),
        eu: base64Encode(eu.publicKey),
      },
      threshold_public_key: base64Encode(threshold.publicKey),
      keylist_aggregate_hash:
        '36f37f451f5ff05088fdc7b59a1b31306484deb4e3d3ee5abd36b81ef7b069b3',
      genesis_ceremony_id: '50ef358e-93f7-4365-8d9f-b23dc09c2b87',
      genesis_timestamp: '2026-04-15T00:00:00Z',
    },
    founder_key_public: base64Encode(founderKp.publicKey),
  };

  const sig = signTrustAnchor(taBase, founderKp.secretKey);
  const trustAnchor: TrustAnchor = { ...taBase, trust_anchor_signature: sig };

  return {
    trustAnchor,
    perNodeKeys: { us, sg, jp, ca, eu },
    thresholdKey: threshold,
  };
}

function buildDirectAttestation(
  fixture: Fixture,
  region: 'us' | 'sg' | 'jp' | 'ca' | 'eu' = 'us',
  payload: unknown = { decision: 'approved', actor: 'model-v1' },
): { attestation: DirectAttestation; payloadHashHex: string } {
  const node = fixture.perNodeKeys[region]!;
  const a: Omit<DirectAttestation, 'signature'> = {
    rubric_version: '1.0',
    attestation_type: 'direct',
    attestation_id: 'att_2026_04_20_a1b2c3d4',
    issuer_node_region: region,
    issued_at: '2026-04-20T14:32:01Z',
    payload,
    publicKey: base64Encode(node.publicKey),
    anchors: {
      hcs: {
        topic_id: '0.0.10416909',
        tx_id: HCS_TX_ID,
        consensus_timestamp: '1714000000.000000000',
        sequence_number: 100,
      },
      base: {
        contract_address: ANCHOR_CONTRACT,
        tx_hash: BASE_TX_HASH,
        block_number: 1,
        block_timestamp: '2026-04-20T14:32:05Z',
      },
    },
  };
  const messageBytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
  });
  const sig = ml_dsa65.sign(node.secretKey, messageBytes);
  const payloadHashHex = hexEncode(sha256(messageBytes));
  return {
    attestation: { ...a, signature: hexEncode(sig) },
    payloadHashHex,
  };
}

/**
 * Build a direct attestation that carries a SIGNED provenance link, exactly as
 * the producer does (provenance is a sibling of payload inside the canonical
 * message). Proves the verifier reconstructs the same bytes (Step 2 fix).
 */
function buildDirectAttestationWithProvenance(
  fixture: Fixture,
  provenance: {
    parents: {
      parent_attestation_id: string;
      parent_payload_hash: string;
      parent_issuer_region: 'us' | 'sg' | 'jp' | 'ca' | 'eu';
      relationship: 'consumed_output' | 'derived_from' | 'aggregated_from';
    }[];
  },
  region: 'us' | 'sg' | 'jp' | 'ca' | 'eu' = 'us',
): { attestation: DirectAttestation; payloadHashHex: string } {
  const node = fixture.perNodeKeys[region]!;
  const payload = { decision: 'approved', actor: 'model-v1' };
  const a: Omit<DirectAttestation, 'signature'> = {
    rubric_version: '1.0',
    attestation_type: 'direct',
    attestation_id: 'att_2026_04_20_a1b2c3d4',
    issuer_node_region: region,
    issued_at: '2026-04-20T14:32:01Z',
    payload,
    provenance,
    publicKey: base64Encode(node.publicKey),
    anchors: {
      hcs: {
        topic_id: '0.0.10416909',
        tx_id: HCS_TX_ID,
        consensus_timestamp: '1714000000.000000000',
        sequence_number: 100,
      },
      base: {
        contract_address: ANCHOR_CONTRACT,
        tx_hash: BASE_TX_HASH,
        block_number: 1,
        block_timestamp: '2026-04-20T14:32:05Z',
      },
    },
  };
  // Sign canonical message INCLUDING provenance (sibling of payload), matching
  // the producer (attestation-publisher signedFields) and the aligned verifier.
  const messageBytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
    provenance: a.provenance,
  });
  const sig = ml_dsa65.sign(node.secretKey, messageBytes);
  const payloadHashHex = hexEncode(sha256(messageBytes));
  return { attestation: { ...a, signature: hexEncode(sig) }, payloadHashHex };
}

describe('verify (provenance-bearing direct attestations — Step 2)', () => {
  const PROV = {
    parents: [
      {
        parent_attestation_id: 'att_2026_04_20_parent00',
        parent_payload_hash: 'a'.repeat(64),
        parent_issuer_region: 'us' as const,
        relationship: 'consumed_output' as const,
      },
    ],
  };

  it('verifies a direct attestation that carries signed provenance', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestationWithProvenance(fixture, PROV);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(true);
    expect(result.details.signature_valid).toBe(true);
  });

  it('rejects when provenance is tampered after signing (spec §5.4 tamper-evidence)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestationWithProvenance(fixture, PROV);
    // Mutate the signed provenance link: signature should no longer verify.
    const tampered: DirectAttestation = {
      ...attestation,
      provenance: {
        parents: [
          {
            parent_attestation_id: 'att_2026_04_20_parent00',
            parent_payload_hash: 'b'.repeat(64),
            parent_issuer_region: 'us' as const,
            relationship: 'consumed_output' as const,
          },
        ],
      },
    };
    const result = await verify({
      attestation: tampered,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.signature_valid).toBe(false);
  });
});

function buildTieredAttestation(
  fixture: Fixture,
): { attestation: TieredAttestation; batchRootHex: string } {
  const region = 'us' as const;
  const node = fixture.perNodeKeys[region]!;

  // 4-leaf batch. Our attestation is leaf index 1.
  const ourPayload = { decision: 'approved', actor: 'model-v1' };
  const otherPayloads = [
    { decision: 'pending', actor: 'model-v1' },
    { decision: 'approved', actor: 'model-v2' },
    { decision: 'denied', actor: 'model-v3' },
  ];

  const ourFields = {
    rubric_version: '1.0',
    attestation_type: 'tiered' as const,
    attestation_id: 'att_2026_04_20_tiered',
    issuer_node_region: region,
    issued_at: '2026-04-20T14:32:01Z',
    payload: ourPayload,
  };
  const ourLeaf = merkleLeaf(canonicalizeBytes(ourFields));
  const otherLeaves = otherPayloads.map((p, i) =>
    merkleLeaf(
      canonicalizeBytes({
        rubric_version: '1.0',
        attestation_type: 'tiered' as const,
        attestation_id: `att_other_${i}`,
        issuer_node_region: region,
        issued_at: '2026-04-20T14:32:01Z',
        payload: p,
      }),
    ),
  );
  const leaves = [otherLeaves[0]!, ourLeaf, otherLeaves[1]!, otherLeaves[2]!]; // our index = 1

  // Build root manually.
  const left01 = merkleInternal(leaves[0]!, leaves[1]!);
  const right23 = merkleInternal(leaves[2]!, leaves[3]!);
  const root = merkleInternal(left01, right23);

  // Inclusion proof for index 1: sibling at leaf level is leaves[0] (L), then sibling is right23 (R).
  const proof = [hexEncode(leaves[0]!), hexEncode(right23)];
  const directions: ('L' | 'R')[] = ['L', 'R'];

  const batchRootHex = hexEncode(root);
  const sig = ml_dsa65.sign(node.secretKey, root);

  const attestation: TieredAttestation = {
    ...ourFields,
    publicKey: base64Encode(node.publicKey),
    signature: hexEncode(sig),
    merkle_proof: proof,
    merkle_proof_directions: directions,
    batch_root: batchRootHex,
    batch_size: 4,
    anchors: {
      hcs: {
        topic_id: '0.0.10416909',
        tx_id: HCS_TX_ID,
        consensus_timestamp: '1714000000.000000000',
        sequence_number: 200,
      },
      base: {
        contract_address: ANCHOR_CONTRACT,
        tx_hash: BASE_TX_HASH,
        block_number: 2,
        block_timestamp: '2026-04-20T14:32:05Z',
      },
    },
  };

  return { attestation, batchRootHex };
}

function buildThresholdAttestation(
  fixture: Fixture,
): { attestation: ThresholdAttestation; payloadHashHex: string } {
  const node = fixture.thresholdKey;
  const region = 'us' as const;
  const a: Omit<ThresholdAttestation, 'signature'> = {
    rubric_version: '1.0',
    attestation_type: 'threshold',
    attestation_id: 'att_2026_04_20_threshold',
    issuer_node_region: region,
    issued_at: '2026-04-20T14:32:01Z',
    payload: { decision: 'approved', actor: 'model-v1' },
    publicKey: base64Encode(node.publicKey),
    threshold_public_key: base64Encode(node.publicKey),
    contributing_node_indices: [1, 2, 3],
    threshold_keylist_hash: fixture.trustAnchor.federation.keylist_aggregate_hash,
    anchors: {
      hcs: {
        topic_id: '0.0.10416909',
        tx_id: HCS_TX_ID,
        consensus_timestamp: '1714000000.000000000',
        sequence_number: 300,
      },
      base: {
        contract_address: ANCHOR_CONTRACT,
        tx_hash: BASE_TX_HASH,
        block_number: 3,
        block_timestamp: '2026-04-20T14:32:05Z',
      },
    },
  };
  const messageBytes = canonicalizeBytes({
    rubric_version: a.rubric_version,
    attestation_type: a.attestation_type,
    attestation_id: a.attestation_id,
    issuer_node_region: a.issuer_node_region,
    issued_at: a.issued_at,
    payload: a.payload,
  });
  const sig = ml_dsa65.sign(node.secretKey, messageBytes);
  const payloadHashHex = hexEncode(sha256(messageBytes));
  return {
    attestation: { ...a, signature: hexEncode(sig) },
    payloadHashHex,
  };
}

/**
 * Build a stub fetch returning canned responses for HCS mirror node and Base RPC.
 *
 * @param hcsPayloadHashHex - hex string the HCS endpoint should return as payload_hash
 * @param baseAggregateRootHex - hex (no 0x) the Base eth_getTransactionReceipt event should report
 */
function makeStubFetch(opts: {
  hcsPayloadHashHex: string | null;
  baseAggregateRootHex: string | null;
  issuerRegion?: 'us' | 'sg' | 'jp' | 'ca' | 'eu';
}): typeof fetch {
  const eventTopic =
    '0x' + hexEncode(keccak256(new TextEncoder().encode('AnchorStored(uint256,bytes32,string,uint64,uint64)')));

  // HCS_TX_ID = '0.0.1234567@1714000000.000000000'
  //   -> initial_transaction_id.account_id            = '0.0.1234567'
  //   -> initial_transaction_id.transaction_valid_start = '1714000000.000000000'
  const TX_ACCOUNT_ID = '0.0.1234567';
  const TX_VALID_START = '1714000000.000000000';
  const region = opts.issuerRegion ?? 'us';

  const stub: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.toString();

    // --- HCS mirror: topic messages endpoint (chunked reassembly) ---
    if (url.includes('/api/v1/topics/') && url.includes('/messages')) {
      // No matching anchor: empty page so reassembly yields null.
      if (opts.hcsPayloadHashHex === null) {
        return new Response(JSON.stringify({ messages: [], links: { next: null } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      // Single-chunk envelope carrying the four cross-checked fields + payload_hash.
      const envelope = {
        attestation_id: 'att_2026_04_20_a1b2c3d4',
        attestation_type: 'direct',
        issuer_node_region: region,
        issued_at: '2026-04-20T14:32:01Z',
        payload_hash: opts.hcsPayloadHashHex,
      };
      const messageB64 = Buffer.from(JSON.stringify(envelope)).toString('base64');
      const body = {
        messages: [
          {
            chunk_info: {
              initial_transaction_id: {
                account_id: TX_ACCOUNT_ID,
                transaction_valid_start: TX_VALID_START,
              },
              number: 1,
              total: 1,
            },
            message: messageB64,
          },
        ],
        links: { next: null },
      };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    // --- Base RPC (unchanged: SP-2 5-field AnchorStored layout) ---
    if (init?.method === 'POST') {
      if (opts.baseAggregateRootHex === null) {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      const root = opts.baseAggregateRootHex;
      const dataHex = '0x' + root;
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            status: '0x1',
            logs: [
              {
                address: ANCHOR_CONTRACT,
                topics: [eventTopic, '0x' + '0'.repeat(63) + '1'], // topics[1]=idx, distinct from root
                data: dataHex,
              },
            ],
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    return new Response('unexpected request', { status: 500 });
  };
  return stub;
}

/* -------------------------------------------------------------------------- */
/* Tests                                                                      */
/* -------------------------------------------------------------------------- */

describe('verify (end-to-end)', () => {
  it('verifies a valid direct attestation', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(true);
    expect(result.failures).toEqual([]);
    expect(result.details.signature_valid).toBe(true);
    expect(result.details.public_key_matches_trust_anchor).toBe(true);
    expect(result.details.hcs_anchor_confirmed).toBe(true);
    expect(result.details.base_anchor_confirmed).toBe(true);
    expect(result.details.anchor_roots_match).toBe(true);
  });

  it('verifies each region (spec §13.5)', async () => {
    const fixture = buildFixture();
    for (const region of ['us', 'sg', 'jp', 'ca', 'eu'] as const) {
      const { attestation, payloadHashHex } = buildDirectAttestation(fixture, region);
      const result = await verify({
        attestation,
        trustAnchor: fixture.trustAnchor,
        access: {
          hederaMirror: 'https://stub',
          baseRpc: 'https://stub',
          fetch: makeStubFetch({
            hcsPayloadHashHex: payloadHashHex,
            baseAggregateRootHex: payloadHashHex,
            issuerRegion: region,
          }),
        },
      });
      expect(result.verified).toBe(true);
    }
  });

  it('rejects a tampered signature (spec §14.1)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const tampered: Attestation = {
      ...attestation,
      signature:
        attestation.signature.slice(0, -2) +
        (attestation.signature.endsWith('00') ? '01' : '00'),
    };
    const result = await verify({
      attestation: tampered,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.signature_valid).toBe(false);
  });

  it('rejects a tampered payload (spec §14.2)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const tampered: Attestation = {
      ...attestation,
      payload: { decision: 'denied', actor: 'model-v1' }, // changed
    };
    const result = await verify({
      attestation: tampered,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.signature_valid).toBe(false);
  });

  it('rejects a wrong public key for the issuer region (spec §14.3)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture, 'us');
    // Substitute SG's pubkey while keeping issuer_node_region = us.
    const sgPub = fixture.trustAnchor.federation.per_node_public_keys.sg;
    const tampered: Attestation = { ...attestation, publicKey: sgPub };
    const result = await verify({
      attestation: tampered,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.public_key_matches_trust_anchor).toBe(false);
  });

  it('rejects HCS-Base anchor disagreement (spec §14.5)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const otherHash = '0'.repeat(64);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: otherHash,
        }),
      },
    });
    expect(result.verified).toBe(false);
  });

  it('rejects a truncated signature without invoking the verify primitive (spec §14.8)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const truncated: Attestation = {
      ...attestation,
      signature: attestation.signature.slice(0, 100), // way short
    };
    const result = await verify({
      attestation: truncated,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.signature_valid).toBe(false);
  });

  it('verifies a valid tiered attestation', async () => {
    const fixture = buildFixture();
    const { attestation, batchRootHex } = buildTieredAttestation(fixture);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: batchRootHex,
          baseAggregateRootHex: batchRootHex,
        }),
      },
    });
    expect(result.verified).toBe(true);
    expect(result.details.merkle_proof_valid).toBe(true);
    expect(result.details.signature_valid).toBe(true);
  });

  it('rejects a tiered attestation with a tampered Merkle proof (spec §14.6)', async () => {
    const fixture = buildFixture();
    const { attestation, batchRootHex } = buildTieredAttestation(fixture);
    const corrupted = attestation.merkle_proof.slice();
    corrupted[0] = (corrupted[0] as string).slice(0, -1) + '0';
    const tampered: TieredAttestation = { ...attestation, merkle_proof: corrupted };
    const result = await verify({
      attestation: tampered,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: batchRootHex,
          baseAggregateRootHex: batchRootHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.merkle_proof_valid).toBe(false);
  });

  it('verifies a valid threshold attestation', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildThresholdAttestation(fixture);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(true);
    expect(result.details.threshold_keylist_hash_matches).toBe(true);
  });

  it('rejects threshold attestation with wrong threshold_keylist_hash (spec §14.7)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildThresholdAttestation(fixture);
    const tampered: ThresholdAttestation = {
      ...attestation,
      threshold_keylist_hash: 'f'.repeat(64),
    };
    const result = await verify({
      attestation: tampered,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.threshold_keylist_hash_matches).toBe(false);
  });

  it('rejects when trust anchor signature is invalid', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const badTa: TrustAnchor = {
      ...fixture.trustAnchor,
      // Flip last byte of signature.
      trust_anchor_signature:
        fixture.trustAnchor.trust_anchor_signature.slice(0, -2) +
        (fixture.trustAnchor.trust_anchor_signature.endsWith('00') ? '01' : '00'),
    };
    const result = await verify({
      attestation,
      trustAnchor: badTa,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.trust_anchor_signature_valid).toBe(false);
  });

  it('accepts single-anchor confirmation when other anchor errors (spec §10.3)', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        allowSingleAnchor: true,
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: null, // RPC errors / no result
        }),
      },
    });
    expect(result.verified).toBe(true);
    expect(result.details.hcs_anchor_confirmed).toBe(true);
    expect(result.details.base_anchor_confirmed).toBe(false);
  });

  it('rejects when both anchors error (spec §10.3 fallthrough)', async () => {
    const fixture = buildFixture();
    const { attestation } = buildDirectAttestation(fixture);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: null,
          baseAggregateRootHex: null,
        }),
      },
    });
    expect(result.verified).toBe(false);
  });

  it('rejects when allowSingleAnchor=false and one anchor errors', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const result = await verify({
      attestation,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        allowSingleAnchor: false,
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: null,
        }),
      },
    });
    expect(result.verified).toBe(false);
  });

  it('rejects an attestation when no trust anchor in history covers issued_at', async () => {
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    // Pass an empty array of trust anchors — by definition no anchor covers
    // any time. We expect VerificationInputError because at-least-one is required.
    await expect(
      verify({
        attestation,
        trustAnchor: [],
        access: {
          hederaMirror: 'https://stub',
          baseRpc: 'https://stub',
          fetch: makeStubFetch({
            hcsPayloadHashHex: payloadHashHex,
            baseAggregateRootHex: payloadHashHex,
          }),
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects when trust-anchor history exists but none covers issued_at', async () => {
    // Build a fully-valid past anchor that ends before the attestation's issued_at.
    // We construct it via the same fixture builder with a different valid_until,
    // re-signing via the fixture's hidden Ed25519 secret. We don't have direct
    // access to that secret here, but we can call `verify` with the existing
    // (valid_until=null) TA and a future attestation issued_at — the temporal
    // check would still match. So instead, test the negative case by manually
    // moving the attestation's issued_at to before valid_from.
    const fixture = buildFixture();
    const { attestation, payloadHashHex } = buildDirectAttestation(fixture);
    const tooEarly: Attestation = { ...attestation, issued_at: '2020-01-01T00:00:00Z' };
    const result = await verify({
      attestation: tooEarly,
      trustAnchor: fixture.trustAnchor,
      access: {
        hederaMirror: 'https://stub',
        baseRpc: 'https://stub',
        fetch: makeStubFetch({
          hcsPayloadHashHex: payloadHashHex,
          baseAggregateRootHex: payloadHashHex,
        }),
      },
    });
    expect(result.verified).toBe(false);
    expect(result.details.trust_anchor_temporally_applicable).toBe(false);
  });
});
