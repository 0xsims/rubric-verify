/**
 * Walk a tiered record's batch_root to the anchored tier-2 aggregate root.
 *
 * Each tier-1 flush contributes an aggregate leaf, chainLeafDigest(
 * 'DOCUMENT_HASH', {forestRoot, itemCount}). Those leaves form a chain tree
 * whose root is self-paired by chainForestWrap to give the value on HCS.
 *
 * The record publishes the flush list so the verifier rebuilds the tree and
 * derives its own inclusion path, rather than trusting a server-supplied one.
 */
import { chainLeafDigest, buildChainTree, chainFold, chainForestWrap }
  from '../chain-merkle.js';

export interface AggregateFlush { forestRoot: string; itemCount: number }

export type InclusionResult =
  | { status: 'confirmed' }
  | { status: 'mismatch'; reason: string }
  | { status: 'indeterminate'; reason: string };

export function checkAggregateInclusion(opts: {
  batchRoot: string;
  batchSize: number;
  tier1Count: number;
  aggregateRoot: string;
  flushes?: AggregateFlush[] | undefined;
}): InclusionResult {
  const { batchRoot, batchSize, tier1Count, aggregateRoot } = opts;
  let list = opts.flushes;
  if ((!list || list.length === 0) && tier1Count === 1) {
    list = [{ forestRoot: batchRoot, itemCount: batchSize }];
  }
  if (!list || list.length === 0) {
    return { status: 'indeterminate', reason:
      `the anchor covers ${String(tier1Count)} tier-1 flushes and this record ` +
      `does not publish the aggregate flush list` };
  }
  if (tier1Count >= 0 && list.length !== tier1Count) {
    return { status: 'indeterminate', reason:
      `flush list has ${String(list.length)} entries but the anchor records ` +
      `tier1Count ${String(tier1Count)}` };
  }
  const want = batchRoot.toLowerCase();
  const idx = list.findIndex((f) => String(f.forestRoot).toLowerCase() === want);
  if (idx < 0) {
    return { status: 'mismatch',
      reason: 'batch_root does not appear in the published aggregate flush list' };
  }
  if (list[idx]!.itemCount !== batchSize) {
    return { status: 'mismatch', reason:
      `flush list itemCount ${String(list[idx]!.itemCount)} does not match ` +
      `batch_size ${String(batchSize)}` };
  }
  const leaves = list.map((f) =>
    chainLeafDigest('DOCUMENT_HASH',
      { forestRoot: f.forestRoot, itemCount: f.itemCount }));
  const walked = chainFold(leaves[idx]!, buildChainTree(leaves).proof(idx));
  const got = chainForestWrap(walked);
  if (got !== aggregateRoot) {
    return { status: 'mismatch', reason:
      `reconstructed aggregate root ${got.slice(0, 16)} does not match ` +
      `anchored ${aggregateRoot.slice(0, 16)}` };
  }
  return { status: 'confirmed' };
}
