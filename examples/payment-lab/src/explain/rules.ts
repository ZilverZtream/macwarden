/**
 * The README rules an explanation cites. Each `name` is quoted exactly as the README names the rule:
 * a bold paragraph heading in "Design decisions" or "Fulfillment" (`**<name>.**`), a section heading
 * (`## <name>`), or a sentence that states the rule (`<name>:` inside a paragraph). `predicates` are the
 * oracle predicates of the state-machine harness (test/harness/oracle.ts) that check the rule, so an
 * explanation's decisions can be matched with what the oracle verifies. test/payment-lab-explain.test.ts
 * checks that every name appears in the README in its form and every predicate in the oracle's table.
 */

export type RuleForm = 'paragraph' | 'section' | 'sentence';

export interface Rule {
  name: string;
  form: RuleForm;
  predicates: readonly string[];
}

export const RULES = {
  durableIntent: { name: 'Durable intent before submission', form: 'paragraph', predicates: ['one-pending-payment-per-operation'] },
  lateInvoice: { name: 'An invoice that turns up late', form: 'paragraph',
    predicates: ['superseded-canceled-never-settled', 'reconcile-buckets-partition'] },
  canceledFinal: { name: 'Canceled is final', form: 'sentence', predicates: ['canceled-final-for-open-accepted'] },
  settledOutranks: { name: 'Settled outranks canceled', form: 'sentence', predicates: ['settled-outranks-canceled'] },
  unresolved: { name: 'Unresolved is a state, not an error', form: 'paragraph',
    predicates: ['one-pending-payment-per-operation', 'reservation-held-iff-live', 'ledger-once-per-succeeded-payment'] },
  timeout: { name: 'A timeout is not a failure', form: 'paragraph', predicates: ['notfound-revert-keeps-live-updates'] },
  compareAndSet: { name: 'SendPaymentV2 is called only by compare-and-set', form: 'paragraph',
    predicates: ['stale-submission-changes-nothing', 'terminal-states-final'] },
  idempotency: { name: 'Idempotency keys', form: 'paragraph', predicates: ['settlement-posted-once', 'ledger-once-per-succeeded-payment'] },
  lookups: { name: 'Subscriptions are a fast path; lookups are the ground truth', form: 'paragraph',
    predicates: ['cursor-moves-only-from-subscription', 'settlement-posted-once'] },
  reservations: { name: 'Reservations', form: 'paragraph', predicates: ['reservation-held-iff-live', 'budget-admission-within-limit'] },
  accounting: { name: 'Accounting from LND\'s numbers', form: 'paragraph', predicates: ['ledger-once-per-succeeded-payment'] },
  ledger: { name: 'Ledger', form: 'section', predicates: ['settlement-posted-once'] },
  fulfillment: { name: 'Fulfillment', form: 'section', predicates: ['settlement-posted-once'] },
  worker: { name: 'The worker', form: 'paragraph', predicates: [] },
} as const satisfies Record<string, Rule>;

export type RuleId = keyof typeof RULES;

/** The rule's name as an explanation prints it. */
export function ruleName(id: RuleId): string {
  return RULES[id].name;
}

/** The rule with this name, if it is one of the table's. */
export function ruleByName(name: string): Rule | undefined {
  return Object.values(RULES).find(rule => rule.name === name);
}
