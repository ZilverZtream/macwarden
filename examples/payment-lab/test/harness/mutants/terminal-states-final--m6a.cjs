// Mutant m6a of the 1.3.0 mutation table (42 mutants): IN_FLIGHT reopens a failed payment.
module.exports = {
  "predicate": "terminal-states-final",
  "description": "IN_FLIGHT reopens a failed payment",
  "edits": [
    [
      "payer/store.ts",
      "      if (record.state === 'failed') return { state: 'failed', completed: false, failed: false, conflicts: [] };",
      ""
    ]
  ]
};
