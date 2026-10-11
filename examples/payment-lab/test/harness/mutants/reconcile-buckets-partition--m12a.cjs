// Mutant m12a of the 1.3.0 mutation table (42 mutants): a canceled invoice is counted open.
module.exports = {
  "predicate": "reconcile-buckets-partition",
  "description": "a canceled invoice is counted open",
  "edits": [
    [
      "receiver/receiver.ts",
      "  return lndState === 'SETTLED' || lndState === 'CANCELED' || (record !== undefined && final(record));",
      "  return lndState === 'SETTLED' || (record !== undefined && record.state === 'settled');"
    ]
  ]
};
