// Mutant m1a of the 1.3.0 mutation table (42 mutants): index excludes intent; recordIntent accepts a replacement while the live one is intent.
module.exports = {
  "predicate": "one-pending-payment-per-operation",
  "description": "index excludes intent; recordIntent accepts a replacement while the live one is intent",
  "edits": [
    [
      "payer/store.ts",
      "  WHERE state IN ('intent', 'submitting', 'in_flight', 'uncertain');",
      "  WHERE state IN ('submitting', 'in_flight', 'uncertain');"
    ],
    [
      "payer/store.ts",
      "        if (live !== undefined && live.state !== 'failed') {",
      "        if (live !== undefined && live.state !== 'failed' && live.state !== 'intent') {"
    ]
  ]
};
