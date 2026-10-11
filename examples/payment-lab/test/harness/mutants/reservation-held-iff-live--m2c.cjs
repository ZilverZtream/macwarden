// Mutant m2c of the 1.3.0 mutation table (42 mutants): prepareRetry takes no new reservation.
module.exports = {
  "predicate": "reservation-held-iff-live",
  "description": "prepareRetry takes no new reservation",
  "edits": [
    [
      "payer/store.ts",
      "        this.#hold(budgetId, operationId, payment.paymentHash, payment.amountMsat, payment.feeLimitMsat, now);",
      ""
    ]
  ]
};
