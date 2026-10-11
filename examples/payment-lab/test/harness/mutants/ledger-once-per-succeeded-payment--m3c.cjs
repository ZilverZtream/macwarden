// Mutant m3c of the 1.3.0 mutation table (42 mutants): principal posted from the record amount instead of LND value_msat.
module.exports = {
  "predicate": "ledger-once-per-succeeded-payment",
  "description": "principal posted from the record amount instead of LND value_msat",
  "edits": [
    [
      "payer/store.ts",
      "        const posting = { operationId: record.operationId, kind, paymentHash: payment.paymentHash, valueMsat: payment.valueMsat, postedAt: now };",
      "        const posting = { operationId: record.operationId, kind, paymentHash: payment.paymentHash, valueMsat: record.amountMsat, postedAt: now };"
    ]
  ]
};
