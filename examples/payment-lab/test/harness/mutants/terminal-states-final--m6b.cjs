// Mutant m6b of the 1.3.0 mutation table (42 mutants): markUncertain moves a failed payment to uncertain.
module.exports = {
  "predicate": "terminal-states-final",
  "description": "markUncertain moves a failed payment to uncertain",
  "edits": [
    [
      "payer/store.ts",
      "        WHERE payment_hash = ? AND state IN ('submitting', 'in_flight', 'uncertain')`).run(reason, nowIso(), paymentHash);",
      "        WHERE payment_hash = ? AND state IN ('submitting', 'in_flight', 'uncertain', 'failed')`).run(reason, nowIso(), paymentHash);"
    ]
  ]
};
