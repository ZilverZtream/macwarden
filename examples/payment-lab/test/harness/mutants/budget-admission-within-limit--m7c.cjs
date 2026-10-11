// Mutant m7c of the 1.3.0 mutation table (42 mutants): prepareRetry skips the budget check.
module.exports = {
  "predicate": "budget-admission-within-limit",
  "description": "prepareRetry skips the budget check",
  "edits": [
    [
      "payer/store.ts",
      "        if (status === undefined || requested > status.availableMsat) {",
      "        if (status === undefined) {"
    ]
  ]
};
