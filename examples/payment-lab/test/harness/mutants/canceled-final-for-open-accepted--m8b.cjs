// Mutant m8b of the 1.3.0 mutation table (42 mutants): a delayed create answer reopens a canceled invoice.
module.exports = {
  "predicate": "canceled-final-for-open-accepted",
  "description": "a delayed create answer reopens a canceled invoice",
  "edits": [
    [
      "receiver/store.ts",
      "      this.db.prepare(`UPDATE invoices SET state = CASE WHEN state = 'creating' THEN 'open'",
      "      this.db.prepare(`UPDATE invoices SET state = CASE WHEN state IN ('creating', 'canceled') THEN 'open'"
    ]
  ]
};
