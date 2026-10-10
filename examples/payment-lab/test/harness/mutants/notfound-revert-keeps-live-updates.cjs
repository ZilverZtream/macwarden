// The 1.2.0 behaviour of a NotFound revert: it closes the submission, so the request still on its way, when it
// reaches LND, speaks for a submission the record no longer listens to, and its IN_FLIGHT and FAILED are dropped.
module.exports = {
  predicate: 'notfound-revert-keeps-live-updates',
  description: 'a NotFound revert to intent closes the live submission',
  edits: [
    ['payer/store.ts', "UPDATE payments SET state = 'intent', uncertain_reason = NULL, updated_at = ?\n        WHERE payment_hash = ? AND state IN ('submitting', 'uncertain')",
      "UPDATE payments SET state = 'intent', uncertain_reason = NULL, closed_submission = submissions, updated_at = ?\n        WHERE payment_hash = ? AND state IN ('submitting', 'uncertain')"],
  ],
};
