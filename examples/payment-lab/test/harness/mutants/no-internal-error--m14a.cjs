// Mutant m14a of the 1.3.0 mutation table (42 mutants): markNotInitiated throws when attempts were recorded.
module.exports = {
  "predicate": "no-internal-error",
  "description": "markNotInitiated throws when attempts were recorded",
  "edits": [
    [
      "payer/store.ts",
      "        this.#event(paymentHash, 'not-found-after-attempts', { evidence });\n        return 'attempts-recorded';",
      "        throw new Error('attempts recorded');"
    ]
  ]
};
