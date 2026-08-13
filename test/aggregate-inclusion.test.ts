import { checkAggregateInclusion } from '../src/anchors/aggregate-inclusion.js';
import { chainLeafDigest, buildChainTree, chainForestWrap }
  from '../src/chain-merkle.js';

const F = [
  { forestRoot: 'aa'.repeat(32), itemCount: 3 },
  { forestRoot: 'bb'.repeat(32), itemCount: 7 },
  { forestRoot: 'cc'.repeat(32), itemCount: 1 },
];
const leaves = F.map((f) => chainLeafDigest('DOCUMENT_HASH', f));
const ROOT = chainForestWrap(buildChainTree(leaves).root);

const base = { batchRoot: F[1]!.forestRoot, batchSize: 7,
  tier1Count: 3, aggregateRoot: ROOT };

describe('aggregate inclusion', () => {
  it('confirms a record inside a multi-flush aggregate', () => {
    expect(checkAggregateInclusion({ ...base, flushes: F }).status)
      .toBe('confirmed');
  });
  it('rejects a tampered sibling', () => {
    const T = F.map((f, i) => (i === 1 ? f : { ...f, forestRoot: 'de'.repeat(32) }));
    expect(checkAggregateInclusion({ ...base, flushes: T }).status)
      .toBe('mismatch');
  });
  it('rejects a batch_root absent from the list', () => {
    expect(checkAggregateInclusion({ ...base, batchRoot: 'ff'.repeat(32), flushes: F })
      .status).toBe('mismatch');
  });
  it('is indeterminate when the list is truncated', () => {
    expect(checkAggregateInclusion({ ...base, flushes: [F[1]!] }).status)
      .toBe('indeterminate');
  });
  it('is indeterminate when the list is absent', () => {
    expect(checkAggregateInclusion({ ...base, flushes: undefined }).status)
      .toBe('indeterminate');
  });
});
