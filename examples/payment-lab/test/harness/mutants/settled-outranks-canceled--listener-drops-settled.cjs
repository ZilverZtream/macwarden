// Pre-1.4 audit (LABHARNESS C): survived the oracle before; listener ignores SETTLED for canceled records.
module.exports = {
  "predicate": "settled-outranks-canceled",
  "description": "listener ignores SETTLED for canceled records",
  "edits": [
    [
      "receiver/receiver.ts",
      "const outcome = apply(deps, invoice, 'subscription');",
      "if (invoice.state === 'SETTLED' && deps.store.invoice(invoice.paymentHash)?.state === 'canceled') return 'continue';\n        const outcome = apply(deps, invoice, 'subscription');"
    ]
  ]
};
