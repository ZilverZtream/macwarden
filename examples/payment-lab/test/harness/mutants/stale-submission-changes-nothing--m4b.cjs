// Mutant m4b of the 1.3.0 mutation table (42 mutants): a stale IN_FLIGHT is applied (only stale FAILED ignored).
module.exports = {
  "predicate": "stale-submission-changes-nothing",
  "description": "a stale IN_FLIGHT is applied (only stale FAILED ignored)",
  "edits": [
    [
      "payer/store.ts",
      "      if (payment.status !== 'SUCCEEDED' && superseded(record, submission)) {",
      "      if (payment.status === 'FAILED' && superseded(record, submission)) {"
    ]
  ]
};
