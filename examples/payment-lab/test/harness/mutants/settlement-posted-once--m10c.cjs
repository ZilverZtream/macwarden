// Mutant m10c of the 1.3.0 mutation table (42 mutants): settlement-amount-conflict guard removed.
module.exports = {
  "predicate": "settlement-posted-once",
  "description": "settlement-amount-conflict guard removed",
  "edits": [
    [
      "receiver/store.ts",
      "      if (settledMsat !== undefined && settledMsat !== invoice.amtPaidMsat) return 'settlement-amount-conflict';",
      "      "
    ]
  ]
};
