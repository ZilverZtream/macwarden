// Mutant m2b of the 1.3.0 mutation table (42 mutants): consume records the fee allowance as the actual fee.
module.exports = {
  "predicate": "reservation-held-iff-live",
  "description": "consume records the fee allowance as the actual fee",
  "edits": [
    [
      "payer/store.ts",
      "      .run(feeMsat, now, reservationId);",
      "      .run(int(row, 'fee_allowance_msat'), now, reservationId);"
    ]
  ]
};
