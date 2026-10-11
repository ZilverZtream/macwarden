// Mutant m2a of the 1.3.0 mutation table (42 mutants): markUncertain releases the reservation (one event early).
module.exports = {
  "predicate": "reservation-held-iff-live",
  "description": "markUncertain releases the reservation (one event early)",
  "edits": [
    [
      "payer/store.ts",
      "      if (changes(result) === 1) this.#event(paymentHash, 'uncertain', { reason });",
      "      if (changes(result) === 1) { this.#event(paymentHash, 'uncertain', { reason }); this.#release(paymentHash, nowIso()); }"
    ]
  ]
};
