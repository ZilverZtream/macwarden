// The 1.4 audit's RECV-A: `receiver settle` checks for displacement only before its lookup. When the record was decided
// not-created while the lookup was out (an older lookup's NotFound landing after the creation window) and a replacement
// was issued, the lookup's ACCEPTED is recorded late-invoice, but the settle goes on: settleRefusal checks only the
// fulfillments and isSuperseded, SettleInvoice is called, the late invoice fulfills the order and the replacement stays
// payable. The oracle catches it at the call (settleCalled: a late invoice settled while its order has another live invoice).
module.exports = {
  "predicate": "superseded-canceled-never-settled",
  "description": "settle: a late ACCEPTED answer for a record decided not-created meanwhile is settled, not canceled (the displacement check after the lookup and settleRefusal's state check removed)",
  "edits": [
    [
      "receiver/receiver.ts",
      "  const displaced = deps.store.invoice(invoice.paymentHash);\n  if (displaced?.state === 'not-created' && before.state !== 'SETTLED') {\n    const late = await resolveLateInvoice(deps, displaced, before, 'lookup');\n    // Adopted (the order had no other live invoice): it is the order's live invoice after all, and is settled as any other.\n    if (late.kind === 'adopted') return await settleHoldInvoice(deps, orderId);\n    return { kind: late.kind === 'unresolved' ? 'unresolved' : 'refused', reason: late.reason };\n  }\n",
      ""
    ],
    [
      "receiver/store.ts",
      "      if (record.state !== 'open' && record.state !== 'accepted') return `invoice ${paymentHash} is ${record.state}, not open or accepted`;\n",
      ""
    ]
  ]
};
