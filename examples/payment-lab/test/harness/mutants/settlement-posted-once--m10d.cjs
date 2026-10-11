// Mutant m10d of the 1.3.0 mutation table (42 mutants): order not marked fulfilled.
module.exports = {
  "predicate": "settlement-posted-once",
  "description": "order not marked fulfilled",
  "edits": [
    [
      "receiver/store.ts",
      "    this.db.prepare(`UPDATE orders SET state = 'fulfilled', fulfilled_at = ? WHERE order_id = ?`).run(now, record.orderId);",
      "    "
    ]
  ]
};
