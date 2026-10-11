// Mutant m10b of the 1.3.0 mutation table (42 mutants): full payment treated as underpaid (<=).
module.exports = {
  "predicate": "settlement-posted-once",
  "description": "full payment treated as underpaid (<=)",
  "edits": [
    [
      "receiver/store.ts",
      "    if (invoice.amtPaidMsat < record.amountMsat) {",
      "    if (invoice.amtPaidMsat <= record.amountMsat) {"
    ]
  ]
};
