// A settlement learned by lookup moves the subscription cursor, so a restarted listener would skip settlements
// it never received (cursor-moves-only-from-subscription.json reconciles one by lookup).
module.exports = {
  predicate: 'cursor-moves-only-from-subscription',
  description: 'a lookup delivery moves the cursor',
  edits: [
    ['receiver/store.ts', "if (source === 'subscription') {", "if (source === 'subscription' || source === 'lookup') {"],
  ],
};
