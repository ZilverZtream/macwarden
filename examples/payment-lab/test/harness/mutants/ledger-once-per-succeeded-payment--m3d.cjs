// Mutant m3d of the 1.3.0 mutation table (42 mutants): a second success is flagged possible-double-payment, never double-payment.
module.exports = {
  "predicate": "ledger-once-per-succeeded-payment",
  "description": "a second success is flagged possible-double-payment, never double-payment",
  "edits": [
    [
      "payer/store.ts",
      "      const action = other.state === 'succeeded' ? 'double-payment' : 'possible-double-payment';",
      "      const action = 'possible-double-payment' as 'double-payment' | 'possible-double-payment';"
    ]
  ]
};
