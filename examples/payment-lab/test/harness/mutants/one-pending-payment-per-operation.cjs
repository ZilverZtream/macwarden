// A replacement invoice is admitted while the operation's payment is still being submitted (and the index that
// enforces one pending payment per operation is no longer unique). The replay one-pending-payment-per-operation.json
// records op0/i1 while op0/i0 is submitting.
module.exports = {
  predicate: 'one-pending-payment-per-operation',
  description: 'recordIntent admits a replacement while the live payment is submitting; the pending-payment index is not unique',
  edits: [
    ['payer/store.ts', 'CREATE UNIQUE INDEX payments_one_pending_per_operation', 'CREATE INDEX payments_one_pending_per_operation'],
    ['payer/store.ts', "if (live !== undefined && live.state !== 'failed') {", "if (live !== undefined && live.state !== 'failed' && live.state !== 'submitting') {"],
  ],
};
