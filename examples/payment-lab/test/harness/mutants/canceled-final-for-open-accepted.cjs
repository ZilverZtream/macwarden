// A replayed OPEN moves a canceled invoice back to open: the delayed answer of the earlier lookup in
// canceled-final-for-open-accepted.json reopens the hold invoice the later lookup recorded canceled.
module.exports = {
  predicate: 'canceled-final-for-open-accepted',
  description: 'an OPEN delivery reopens a canceled invoice',
  edits: [
    ['receiver/store.ts', "if (!blocked && (RANK[next] > RANK[record.state] || (record.state === 'creating' && next === 'open'))) {",
      "if (!blocked && (RANK[next] > RANK[record.state] || (record.state === 'creating' && next === 'open') || (record.state === 'canceled' && next === 'open'))) {"],
  ],
};
