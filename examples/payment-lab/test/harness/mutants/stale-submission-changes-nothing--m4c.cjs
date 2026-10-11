// Mutant m4c of the 1.3.0 mutation table (42 mutants): markRejected ignores supersession.
module.exports = {
  "predicate": "stale-submission-changes-nothing",
  "description": "markRejected ignores supersession",
  "edits": [
    [
      "payer/store.ts",
      "      if (record === undefined) return false;\n      if (superseded(record, submission)) {",
      "      if (record === undefined) return false;\n      if (false) {"
    ]
  ]
};
