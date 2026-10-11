// Mutant m3b of the 1.3.0 mutation table (42 mutants): success after a recorded failure does not complete the operation.
module.exports = {
  "predicate": "ledger-once-per-succeeded-payment",
  "description": "success after a recorded failure does not complete the operation",
  "edits": [
    [
      "payer/store.ts",
      "          WHERE operation_id = ? AND state <> 'completed'`).run(now, now, record.operationId)) === 1;",
      "          WHERE operation_id = ? AND state <> 'completed' AND state <> 'failed'`).run(now, now, record.operationId)) === 1;"
    ]
  ]
};
