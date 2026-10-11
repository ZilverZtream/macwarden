// Mutant m12c of the 1.3.0 mutation table (42 mutants): late (not-created) candidates left out of the targets.
module.exports = {
  "predicate": "reconcile-buckets-partition",
  "description": "late (not-created) candidates left out of the targets",
  "edits": [
    [
      "receiver/receiver.ts",
      "    ? [...deps.store.unresolvedInvoices(), ...deps.store.lateInvoiceCandidates(recheckSince)]",
      "    ? [...deps.store.unresolvedInvoices()]"
    ]
  ]
};
