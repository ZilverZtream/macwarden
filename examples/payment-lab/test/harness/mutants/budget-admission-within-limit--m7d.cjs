// Mutant m7d of the 1.3.0 mutation table (42 mutants): budgetStatus held sum through Number (float).
module.exports = {
  "predicate": "budget-admission-within-limit",
  "description": "budgetStatus held sum through Number (float)",
  "edits": [
    [
      "payer/store.ts",
      "      if (text(row, 'state') === 'held') heldMsat += int(row, 'principal_msat') + int(row, 'fee_allowance_msat');",
      "      if (text(row, 'state') === 'held') heldMsat = BigInt(Number(heldMsat) + Number(int(row, 'principal_msat') + int(row, 'fee_allowance_msat')));"
    ]
  ]
};
