// Mutant m8d of the 1.3.0 mutation table (42 mutants): late CANCELED overwritten by a later OPEN/ACCEPTED.
module.exports = {
  "predicate": "canceled-final-for-open-accepted",
  "description": "late CANCELED overwritten by a later OPEN/ACCEPTED",
  "edits": [
    [
      "receiver/store.ts",
      "const LND_RANK: Record<string, number> = { OPEN: 1, ACCEPTED: 1, CANCELED: 3, SETTLED: 4 };",
      "const LND_RANK: Record<string, number> = { OPEN: 1, ACCEPTED: 1, CANCELED: 0, SETTLED: 4 };"
    ],
    [
      "receiver/store.ts",
      "      && (late === 'CANCELED' || (LND_RANK[invoice.state] ?? 0) < (LND_RANK[late] ?? 0));",
      "      && ((LND_RANK[invoice.state] ?? 0) < (LND_RANK[late] ?? 0));"
    ],
    [
      "receiver/store.ts",
      "          payment_request = COALESCE(payment_request, ?), updated_at = ? WHERE payment_hash = ? AND (${LATE_RANK('?')} > ${LATE_RANK('late_lnd_state')}",
      "          payment_request = COALESCE(payment_request, ?), updated_at = ? WHERE payment_hash = ? AND (late_lnd_state = 'CANCELED' OR ${LATE_RANK('?')} > ${LATE_RANK('late_lnd_state')}"
    ]
  ]
};
