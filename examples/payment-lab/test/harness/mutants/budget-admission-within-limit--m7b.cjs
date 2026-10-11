// Mutant m7b of the 1.3.0 mutation table (42 mutants): off by one: refuses when requested == available.
module.exports = {
  "predicate": "budget-admission-within-limit",
  "description": "off by one: refuses when requested == available",
  "edits": [
    [
      "payer/store.ts",
      "        if (requested > status.availableMsat) {",
      "        if (requested >= status.availableMsat) {"
    ]
  ]
};
