// Mutant m8c of the 1.3.0 mutation table (42 mutants): a late invoice LND canceled is overwritten / adopted by a replayed OPEN.
module.exports = {
  "predicate": "canceled-final-for-open-accepted",
  "description": "a late invoice LND canceled is overwritten / adopted by a replayed OPEN",
  "edits": [
    [
      "receiver/store.ts",
      "  `CASE ${expression} WHEN 'OPEN' THEN 1 WHEN 'ACCEPTED' THEN 1 WHEN 'CANCELED' THEN 3 WHEN 'SETTLED' THEN 4 ELSE 0 END`;",
      "  `CASE ${expression} WHEN 'OPEN' THEN 1 WHEN 'ACCEPTED' THEN 1 WHEN 'CANCELED' THEN 0 WHEN 'SETTLED' THEN 4 ELSE 0 END`;"
    ],
    [
      "receiver/store.ts",
      "      && (late === 'CANCELED' || (LND_RANK[invoice.state] ?? 0) < (LND_RANK[late] ?? 0));",
      "      && ((LND_RANK[invoice.state] ?? 0) < (LND_RANK[late] ?? 0));"
    ]
  ]
};
