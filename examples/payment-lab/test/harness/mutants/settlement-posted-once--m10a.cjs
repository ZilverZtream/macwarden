// Mutant m10a of the 1.3.0 mutation table (42 mutants): a second-payment also inserts a fulfillment.
module.exports = {
  "predicate": "settlement-posted-once",
  "description": "a second-payment also inserts a fulfillment",
  "edits": [
    [
      "receiver/store.ts",
      "      if (posted) post(this.db, receiverDoublePayment(posting));",
      "      if (posted) { post(this.db, receiverDoublePayment(posting)); this.db.prepare('INSERT INTO fulfillments (payment_hash, order_id, fulfilled_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING').run(invoice.paymentHash, record.orderId, now); }"
    ]
  ]
};
