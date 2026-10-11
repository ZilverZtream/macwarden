// Mutant m13b of the 1.3.0 mutation table (42 mutants): settle: no superseded check at all.
module.exports = {
  "predicate": "superseded-canceled-never-settled",
  "description": "settle: no superseded check at all",
  "edits": [
    [
      "receiver/receiver.ts",
      "  if (typeof invoice !== 'string' && deps.store.isSuperseded(invoice.paymentHash)) {",
      "  if (false) {"
    ],
    [
      "receiver/receiver.ts",
      "  const refusal = deps.store.settleRefusal(invoice.paymentHash);",
      "  const refusal = undefined as string | undefined;"
    ]
  ]
};
