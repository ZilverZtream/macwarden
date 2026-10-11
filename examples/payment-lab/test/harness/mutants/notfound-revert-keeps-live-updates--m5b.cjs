// Mutant m5b of the 1.3.0 mutation table (42 mutants): IN_FLIGHT ignored for a record back in intent.
module.exports = {
  "predicate": "notfound-revert-keeps-live-updates",
  "description": "IN_FLIGHT ignored for a record back in intent",
  "edits": [
    [
      "payer/store.ts",
      "      if (record.state === 'failed') return { state: 'failed', completed: false, failed: false, conflicts: [] };",
      "      if (record.state === 'failed') return { state: 'failed', completed: false, failed: false, conflicts: [] };\n      if (record.state === 'intent') return { state: 'intent', completed: false, failed: false, conflicts: [] };"
    ]
  ]
};
