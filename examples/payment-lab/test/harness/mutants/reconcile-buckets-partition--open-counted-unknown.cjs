// Pre-1.4 audit (LABHARNESS D): survived the oracle before; open counted as unknown.
module.exports = {
  "predicate": "reconcile-buckets-partition",
  "description": "open counted as unknown",
  "edits": [
    [
      "receiver/receiver.ts",
      "buckets.set(paymentHash, decided(deps, paymentHash, found.state) ? 'resolved' : 'open');",
      "buckets.set(paymentHash, decided(deps, paymentHash, found.state) ? 'resolved' : 'unknown');"
    ]
  ]
};
