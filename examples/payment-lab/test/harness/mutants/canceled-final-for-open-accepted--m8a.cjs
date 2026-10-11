// Mutant m8a of the 1.3.0 mutation table (42 mutants): CANCELED reopens on ACCEPTED when the amount matches.
module.exports = {
  "predicate": "canceled-final-for-open-accepted",
  "description": "CANCELED reopens on ACCEPTED when the amount matches",
  "edits": [
    [
      "receiver/store.ts",
      "    }\n    let outcome: DeliveryOutcome = 'unchanged';",
      "    }\n    if (record.state === 'canceled' && next === 'accepted' && invoice.amtPaidMsat === record.amountMsat) { this.db.prepare(`UPDATE invoices SET state = 'accepted', updated_at = ? WHERE payment_hash = ?`).run(now, invoice.paymentHash); return 'state-updated'; }\n    let outcome: DeliveryOutcome = 'unchanged';"
    ]
  ]
};
