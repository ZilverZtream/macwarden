// Mutant m4a of the 1.3.0 mutation table (42 mutants): superseded() ignores closed_submission.
module.exports = {
  "predicate": "stale-submission-changes-nothing",
  "description": "superseded() ignores closed_submission",
  "edits": [
    [
      "payer/store.ts",
      "  return submission < record.submissions || (record.closedSubmission > 0 && submission <= record.closedSubmission);",
      "  return submission < record.submissions;"
    ]
  ]
};
