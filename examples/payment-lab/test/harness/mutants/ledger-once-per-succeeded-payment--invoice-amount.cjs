// Pre-1.4 audit (LABHARNESS B): survived the oracle before; success recorded at the invoice amount instead of LND value.
module.exports = {
  "predicate": "ledger-once-per-succeeded-payment",
  "description": "success recorded at the invoice amount instead of LND value",
  "edits": [
    [
      "payer/store.ts",
      ".run(payment.feeMsat, payment.valueMsat, preimage",
      ".run(payment.feeMsat, record.amountMsat, preimage"
    ],
    [
      "payer/store.ts",
      "paymentHash: payment.paymentHash, valueMsat: payment.valueMsat, postedAt: now };",
      "paymentHash: payment.paymentHash, valueMsat: record.amountMsat, postedAt: now };"
    ],
    [
      "payer/store.ts",
      "valueMsat: payment.valueMsat, feeMsat: payment.feeMsat, ledgerEntryId: entryId",
      "valueMsat: record.amountMsat, feeMsat: payment.feeMsat, ledgerEntryId: entryId"
    ],
    [
      "payer/store.ts",
      "this.#consume(payment.paymentHash, payment.valueMsat,",
      "this.#consume(payment.paymentHash, record.amountMsat,"
    ],
    [
      "payer/store.ts",
      "record.feeMsat !== payment.feeMsat || record.valueMsat !== payment.valueMsat",
      "record.feeMsat !== payment.feeMsat"
    ]
  ]
};
