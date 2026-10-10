// The worker acknowledges a row it claims again (after a worker died holding it) without performing its effect:
// the row is done and its receipt or confirmation is never written.
module.exports = {
  predicate: 'effects-once',
  description: 'a row claimed a second time is acknowledged without its effect',
  edits: [
    ['outbox/worker.ts', 'outcome = publish(target, row.subject, effectFields(row), hooks,', "outcome = row.attempts > 1 ? 'already-present' : publish(target, row.subject, effectFields(row), hooks,"],
  ],
};
