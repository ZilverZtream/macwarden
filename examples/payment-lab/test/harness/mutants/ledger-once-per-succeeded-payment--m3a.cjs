// Mutant m3a of the 1.3.0 mutation table (42 mutants): every success also posts a double-payment journal entry (a second posting under another event).
module.exports = {
  "predicate": "ledger-once-per-succeeded-payment",
  "description": "every success also posts a double-payment journal entry (a second posting under another event)",
  "edits": [
    [
      "payer/store.ts",
      "        if (conflicts.some(item => item.action === 'double-payment')) post(this.db, payerDoublePayment(posting));",
      "        post(this.db, payerDoublePayment(posting));"
    ]
  ]
};
