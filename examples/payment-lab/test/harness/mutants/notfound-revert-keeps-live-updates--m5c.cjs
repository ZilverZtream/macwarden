// Mutant m5c of the 1.3.0 mutation table (42 mutants): FAILED / definite refusal ignored for a record back in intent.
module.exports = {
  "predicate": "notfound-revert-keeps-live-updates",
  "description": "FAILED / definite refusal ignored for a record back in intent",
  "edits": [
    [
      "payer/store.ts",
      "      uncertain_reason = NULL, resolved_at = ?, updated_at = ? WHERE payment_hash = ? AND state NOT IN ('failed', 'succeeded')`)",
      "      uncertain_reason = NULL, resolved_at = ?, updated_at = ? WHERE payment_hash = ? AND state NOT IN ('failed', 'succeeded', 'intent')`)"
    ]
  ]
};
