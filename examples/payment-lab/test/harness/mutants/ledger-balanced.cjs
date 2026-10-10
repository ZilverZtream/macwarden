// A consumed reservation's entry releases the whole fee allowance instead of the unused part, so the budget
// account no longer commits principal plus the actual fee. The reservation rows and the payment's own legs are
// right, so only ledger verify (the predicate ledger-balanced) sees it.
module.exports = {
  predicate: 'ledger-balanced',
  description: 'budget-consumed releases the whole fee allowance, not allowance minus the actual fee',
  edits: [
    ['ledger/postings.ts', 'const unused = input.allowanceMsat - input.feeMsat;', 'const unused = input.allowanceMsat;'],
  ],
};
