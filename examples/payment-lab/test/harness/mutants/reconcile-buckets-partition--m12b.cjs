// Mutant m12b of the 1.3.0 mutation table (42 mutants): CLI exits 0 with one unknown.
module.exports = {
  "predicate": "reconcile-buckets-partition",
  "description": "CLI exits 0 with one unknown",
  "edits": [
    [
      "cli.ts",
      "        return result.unknown > 0 ? EXIT.unresolved : EXIT.ok;",
      "        return result.unknown > 1 ? EXIT.unresolved : EXIT.ok;"
    ]
  ]
};
