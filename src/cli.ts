#!/usr/bin/env node
/**
 * rubric-verify CLI — independent verification of a Rubric attestation.
 *
 * Usage:
 *   rubric-verify <attestation-id | path/to/attestation.json> [options]
 *
 * Options:
 *   --json                  machine-readable output
 *   --anchor <url|file>     trust anchor source (default: https://rubric-protocol.com/trust-anchor.json)
 *   --api <base-url>        attestation retrieval API (default: https://us.rubric-protocol.com)
 *   --allow-single-anchor   accept HCS-only anchoring explicitly
 *
 * Exit codes: 0 = verified, 1 = verification failed, 2 = operational error.
 *
 * The retrieval API is used ONLY to fetch attestation bytes. Any verdict
 * fields in the server envelope are discarded; verification runs locally
 * in this process against the published trust anchor and the Hedera
 * public mirror node.
 */
import { readFileSync, existsSync } from 'fs';
import { verify } from './index.js';

const DEFAULT_ANCHOR = 'https://rubric-protocol.com/trust-anchor.json';
const DEFAULT_API = 'https://us.rubric-protocol.com';

interface CliOpts {
  target: string;
  json: boolean;
  anchor: string;
  api: string;
  allowSingleAnchor: boolean;
}

function usage(): void {
  process.stderr.write(
    'usage: rubric-verify <attestation-id | attestation.json> ' +
      '[--json] [--anchor <url|file>] [--api <base-url>] [--allow-single-anchor]\n'
  );
}

function die(code: number, msg: string): never {
  process.stderr.write(`rubric-verify: ${msg}\n`);
  process.exit(code);
}

function parseArgs(argv: string[]): CliOpts {
  let target = '';
  const o = { json: false, anchor: DEFAULT_ANCHOR, api: DEFAULT_API, allowSingleAnchor: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a === '--json') o.json = true;
    else if (a === '--allow-single-anchor') o.allowSingleAnchor = true;
    else if (a === '--anchor') { const v = argv[++i]; if (!v) die(2, '--anchor requires a value'); o.anchor = v; }
    else if (a === '--api') { const v = argv[++i]; if (!v) die(2, '--api requires a value'); o.api = v.replace(/\/+$/, ''); }
    else if (a === '--help' || a === '-h') { usage(); process.exit(0); }
    else if (a.startsWith('--')) die(2, `unknown option: ${a}`);
    else if (!target) target = a;
    else die(2, `unexpected argument: ${a}`);
  }
  if (!target) { usage(); process.exit(2); }
  return { target, ...o };
}

async function loadJson(source: string): Promise<unknown> {
  if (/^https?:\/\//.test(source)) {
    const res = await fetch(source);
    if (!res.ok) die(2, `fetch ${source} -> HTTP ${res.status}`);
    return res.json();
  }
  return JSON.parse(readFileSync(source, 'utf8'));
}

async function loadAttestation(opts: CliOpts): Promise<Record<string, unknown>> {
  if (existsSync(opts.target)) {
    const parsed = (await loadJson(opts.target)) as Record<string, unknown>;
    // Accept either a raw attestation or a saved API envelope.
    if (parsed && typeof parsed === 'object' && 'attestation' in parsed) {
      return parsed['attestation'] as Record<string, unknown>;
    }
    return parsed;
  }
  const url = `${opts.api}/v1/verify/${encodeURIComponent(opts.target)}`;
  const res = await fetch(url);
  if (!res.ok) die(2, `attestation retrieval failed: ${url} -> HTTP ${res.status}`);
  const envelope = (await res.json()) as Record<string, unknown>;
  if (!envelope['found'] || !envelope['attestation']) {
    die(2, `attestation not found: ${opts.target}`);
  }
  // Server verdict fields are intentionally discarded.
  return envelope['attestation'] as Record<string, unknown>;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const attestation = await loadAttestation(opts);
  const trustAnchor = await loadJson(opts.anchor);

  const input: Record<string, unknown> = { attestation, trustAnchor };
  if (opts.allowSingleAnchor) input['access'] = { allowSingleAnchor: true };

  const result = (await verify(input as never)) as {
    verified: boolean;
    failures?: unknown;
    reason?: unknown;
    details?: unknown;
  };

  if (opts.json) {
    process.stdout.write(JSON.stringify({ target: opts.target, ...result }, null, 2) + '\n');
  } else {
    const att = attestation as { attestation_type?: string; issued_at?: string; anchors?: { hcs?: { topic_id?: string; sequence_number?: number } } };
    process.stdout.write('=== RUBRIC INDEPENDENT VERIFICATION ===\n');
    process.stdout.write(`attestation:   ${opts.target}\n`);
    if (att.attestation_type) process.stdout.write(`type:          ${att.attestation_type}\n`);
    if (att.issued_at) process.stdout.write(`issued_at:     ${att.issued_at}\n`);
    if (att.anchors?.hcs) process.stdout.write(`hcs_anchor:    topic ${att.anchors.hcs.topic_id ?? '?'} seq ${att.anchors.hcs.sequence_number ?? '?'}\n`);
    process.stdout.write(`trust_anchor:  ${opts.anchor}\n`);
    process.stdout.write('verification:  performed locally in this process\n');
    process.stdout.write('---\n');
    process.stdout.write(`VERIFIED: ${result.verified}\n`);
    const findings = result.failures ?? result.reason ?? null;
    if (findings && (!Array.isArray(findings) || findings.length > 0)) {
      const label = result.verified ? 'notes (non-fatal)' : 'failures';
      process.stdout.write(`${label}: ${JSON.stringify(findings)}\n`);
    }
  }
  process.exit(result.verified ? 0 : 1);
}

main().catch((err: unknown) => {
  die(2, err instanceof Error ? err.message : String(err));
});
