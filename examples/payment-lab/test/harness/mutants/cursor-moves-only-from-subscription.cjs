// A settlement learned by lookup counts for the settle cursor: once the subscription delivers a later settlement, the
// cursor moves over the lookup's settle index too, so a restarted listener would skip settlements the subscription
// never delivered (cursor-moves-only-from-subscription.json: settlement 2 by lookup, then the subscription's 3).
module.exports = {
  predicate: 'cursor-moves-only-from-subscription',
  description: 'a lookup delivery counts for the settle cursor',
  edits: [
    ['receiver/store.ts', "FROM deliveries WHERE source = 'subscription' AND settle_index = ? LIMIT 1", 'FROM deliveries WHERE settle_index = ? LIMIT 1'],
  ],
};
