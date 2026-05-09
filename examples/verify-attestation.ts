/**
 * Example: verify an attestation from JSON files on disk.
 *
 * Usage:
 *   npx tsx examples/verify-attestation.ts ./attestation.json ./trust-anchor.json
 *
 * Or after build:
 *   node --loader ts-node/esm examples/verify-attestation.ts ./attestation.json ./trust-anchor.json
 *
 * Both inputs are JSON-encoded:
 *   - attestation.json:   the Attestation record returned by Rubric Proof
 *   - trust-anchor.json:  the published Rubric trust anchor (single object,
 *                         or an array for trust anchor history)
 *
 * Exit codes:
 *   0  -> verified
 *   1  -> not verified (with diagnostics on stderr)
 *   2  -> input error or runtime exception
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { verify } from '../src/index.js';
import type { Attestation, TrustAnchor } from '../src/index.js';

async function main(): Promise<number> {
  const [, , attestationPath, trustAnchorPath] = process.argv;
  if (!attestationPath || !trustAnchorPath) {
    console.error('Usage: verify-attestation.ts <attestation.json> <trust-anchor.json>');
    return 2;
  }

  let attestation: Attestation;
  let trustAnchor: TrustAnchor | TrustAnchor[];
  try {
    attestation = JSON.parse(
      await readFile(resolve(attestationPath), 'utf-8'),
    ) as Attestation;
    trustAnchor = JSON.parse(
      await readFile(resolve(trustAnchorPath), 'utf-8'),
    ) as TrustAnchor | TrustAnchor[];
  } catch (e) {
    console.error('Failed to read or parse input:', (e as Error).message);
    return 2;
  }

  let result;
  try {
    result = await verify({ attestation, trustAnchor });
  } catch (e) {
    console.error('Verification threw:', (e as Error).message);
    return 2;
  }

  if (result.verified) {
    console.log(`✓ verified  ${result.attestation_id}`);
    console.log('  details:', JSON.stringify(result.details, null, 2));
    return 0;
  }

  console.error(`✗ NOT verified  ${result.attestation_id}`);
  console.error('  failures:');
  for (const f of result.failures) console.error('    -', f);
  console.error('  details:', JSON.stringify(result.details, null, 2));
  return 1;
}

main()
  .then((code) => process.exit(code))
  .catch((e: unknown) => {
    console.error('Fatal:', e);
    process.exit(2);
  });
