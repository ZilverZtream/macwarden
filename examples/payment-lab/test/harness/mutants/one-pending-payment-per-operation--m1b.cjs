// Mutant m1b of the 1.3.0 mutation table (42 mutants): index not unique; recordIntent accepts a replacement while the live one is uncertain.
module.exports = {
  "predicate": "one-pending-payment-per-operation",
  "description": "index not unique; recordIntent accepts a replacement while the live one is uncertain",
  "edits": [
    [
      "payer/store.ts",
      "CREATE UNIQUE INDEX payments_one_pending_per_operation ON payments (operation_id)",
      "CREATE INDEX payments_one_pending_per_operation ON payments (operation_id)"
    ],
    [
      "payer/store.ts",
      "        if (live !== undefined && live.state !== 'failed') {",
      "        if (live !== undefined && live.state !== 'failed' && live.state !== 'uncertain') {"
    ]
  ]
};
