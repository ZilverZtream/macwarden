// Mutant m14b of the 1.3.0 mutation table (42 mutants): markCreated throws when the record is canceled.
module.exports = {
  "predicate": "no-internal-error",
  "description": "markCreated throws when the record is canceled",
  "edits": [
    [
      "receiver/store.ts",
      "      return this.invoice(paymentHash)?.state;",
      "      const s = this.invoice(paymentHash)?.state; if (s === 'canceled') throw new Error('canceled'); return s;"
    ]
  ]
};
