// Pre-1.4 audit (LABHARNESS A): survived the oracle before; recordIntent takes no reservation.
module.exports = {
  "predicate": "reservation-held-iff-live",
  "description": "recordIntent takes no reservation",
  "edits": [
    [
      "payer/store.ts",
      "this.#hold(input.budgetId, input.operationId, hash, input.invoice.amountMsat, input.feeLimitMsat, now);",
      "/* no hold */"
    ]
  ]
};
