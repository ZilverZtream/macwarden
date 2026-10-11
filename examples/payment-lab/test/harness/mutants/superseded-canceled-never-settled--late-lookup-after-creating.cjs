// The 1.3.1 audit's F07: reconcile decides the late-invoice path from the record snapshot taken before its lookup. A pass
// that listed the invoice `creating` and gets OPEN after an older NotFound decided it not-created (and a replacement was
// issued) records late-invoice but never enters resolveLateInvoice: the invoice stays payable beside its replacement
// until a later pass. The oracle catches it within the pass (reconcileDone: late-invoice recorded, no CancelInvoice).
module.exports = {
  "predicate": "superseded-canceled-never-settled",
  "description": "reconcile: a creating invoice's late OPEN answer is recorded, not canceled, when the record was decided not-created meanwhile",
  "edits": [
    [
      "receiver/receiver.ts",
      "    const state = invoice.state === 'creating' ? deps.store.markCreated(paymentHash, found.paymentRequest, found.addIndex) : invoice.state;\n    if (state === 'not-created') {\n      const result = await resolveLateInvoice(deps, deps.store.invoice(paymentHash) ?? invoice, found, 'lookup', pass);\n      buckets.set(paymentHash, result.kind === 'unresolved' ? 'unknown' : decided(deps, paymentHash, found.state) ? 'resolved' : 'open');\n      continue;\n    }\n",
      "    if (invoice.state === 'creating') deps.store.markCreated(paymentHash, found.paymentRequest, found.addIndex);\n"
    ]
  ]
};
