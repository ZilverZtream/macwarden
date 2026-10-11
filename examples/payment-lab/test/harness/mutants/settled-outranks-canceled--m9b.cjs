// Mutant m9b of the 1.3.0 mutation table (42 mutants): late_lnd_state CANCELED not moved by SETTLED.
module.exports = {
  "predicate": "settled-outranks-canceled",
  "description": "late_lnd_state CANCELED not moved by SETTLED",
  "edits": [
    [
      "receiver/store.ts",
      "  `CASE ${expression} WHEN 'OPEN' THEN 1 WHEN 'ACCEPTED' THEN 1 WHEN 'CANCELED' THEN 3 WHEN 'SETTLED' THEN 4 ELSE 0 END`;",
      "  `CASE ${expression} WHEN 'OPEN' THEN 1 WHEN 'ACCEPTED' THEN 1 WHEN 'CANCELED' THEN 3 WHEN 'SETTLED' THEN 3 ELSE 0 END`;"
    ]
  ]
};
