// Mutant m13a of the 1.3.0 mutation table (42 mutants): settle: no re-check after the lookup.
module.exports = {
  "predicate": "superseded-canceled-never-settled",
  "description": "settle: no re-check after the lookup",
  "edits": [
    [
      "receiver/receiver.ts",
      "  const refusal = deps.store.settleRefusal(invoice.paymentHash);",
      "  const refusal = undefined as string | undefined;"
    ]
  ]
};
