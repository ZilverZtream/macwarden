// Mutant m7a of the 1.3.0 mutation table (42 mutants): budget check skipped when the limit is 2^63-1.
module.exports = {
  "predicate": "budget-admission-within-limit",
  "description": "budget check skipped when the limit is 2^63-1",
  "edits": [
    [
      "payer/store.ts",
      "        if (requested > status.availableMsat) {",
      "        if (requested > status.availableMsat && status.limitMsat !== 9223372036854775807n) {"
    ]
  ]
};
