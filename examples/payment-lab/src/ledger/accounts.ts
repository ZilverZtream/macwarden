/**
 * The chart of accounts, shared by the payer's and the receiver's books. Each store keeps its
 * own journal (its own SQLite file), but both post to these accounts only, so an account name
 * means the same thing in every book.
 *
 * Balances are reported as net debit (debits minus credits): positive for an account that
 * was debited more than credited, negative otherwise. Nothing here is a sign convention a
 * reader has to remember per account.
 *
 * | Account                 | Debited when                                   | Credited when                                  |
 * | ----------------------- | ---------------------------------------------- | ---------------------------------------------- |
 * | customer-receivable     | the payer pays an order; the receiver moves a   | the receiver is paid for an order; the payer   |
 * |                         | second payment for an order to suspense         | moves a second payment for an order to suspense|
 * | lnd-wallet-incoming     | an invoice settles (LND's amt_paid_msat)        | never                                          |
 * | lnd-wallet-outgoing     | never                                           | a payment succeeds (value, and fee separately) |
 * | routing-fees            | a payment succeeds (LND's fee_msat)             | never                                          |
 * | refunds-payable         | a refund payment succeeds                       | a second refund payment is moved to suspense   |
 * | payouts-payable         | a payout payment succeeds                       | a second payout payment is moved to suspense   |
 * | suspense-double-payment | the payer paid an operation twice               | the receiver was paid twice for an order       |
 * | budget:<id>             | a reservation is held; a consumed fee exceeds   | a reservation is released; a consumed fee is   |
 * |                         | its allowance; a released one is consumed       | below its allowance                            |
 * | budget-commitments      | the opposite of budget:<id>                     | the opposite of budget:<id>                    |
 *
 * customer-receivable is the clearing account between the two books: for one order paid by
 * the lab's payer and received by the lab's receiver it nets to zero across both. A double
 * payment is moved out of it into suspense-double-payment (debit on the payer, money that
 * left twice; credit on the receiver, money that arrived twice and is to be returned).
 *
 * budget:<id> carries what budget <id> has committed (held plus consumed reservations), so its
 * balance equals limit minus available, which `ledger verify` checks against the reservations.
 */

export const ACCOUNT = {
  customerReceivable: 'customer-receivable',
  walletIncoming: 'lnd-wallet-incoming',
  walletOutgoing: 'lnd-wallet-outgoing',
  routingFees: 'routing-fees',
  refundsPayable: 'refunds-payable',
  payoutsPayable: 'payouts-payable',
  suspenseDoublePayment: 'suspense-double-payment',
  budgetCommitments: 'budget-commitments',
} as const;

export type FixedAccount = typeof ACCOUNT[keyof typeof ACCOUNT];

const FIXED: ReadonlySet<string> = new Set(Object.values(ACCOUNT));
const BUDGET_PREFIX = 'budget:';
/** What the budgets table accepts (CHECK length 1-128); the CLI narrows it further to identifiers. */
const validBudgetId = (id: string): boolean => id.length >= 1 && id.length <= 128;

/** The account of one budget. */
export function budgetAccount(budgetId: string): string {
  if (!validBudgetId(budgetId)) throw new Error('a budget ID is 1 to 128 characters');
  return `${BUDGET_PREFIX}${budgetId}`;
}

/** The budget ID of a budget account, or undefined for any other account. */
export function budgetOf(account: string): string | undefined {
  if (!account.startsWith(BUDGET_PREFIX)) return undefined;
  const id = account.slice(BUDGET_PREFIX.length);
  return validBudgetId(id) ? id : undefined;
}

/** Whether `account` is in the chart: a fixed account or a well-formed budget account. */
export function isAccount(account: string): boolean {
  return FIXED.has(account) || budgetOf(account) !== undefined;
}

/** The account a succeeded payment of this operation kind settles (payer side). */
export function counterAccountFor(kind: 'order-payment' | 'refund' | 'payout'): FixedAccount {
  switch (kind) {
    case 'order-payment': return ACCOUNT.customerReceivable;
    case 'refund': return ACCOUNT.refundsPayable;
    case 'payout': return ACCOUNT.payoutsPayable;
  }
}

/** Journal events. Every entry names the one that caused it; (event, reference) is unique, which makes posting idempotent. */
export const EVENTS = [
  'invoice-settled', 'underpaid-settlement', 'payment-succeeded', 'double-payment',
  'budget-held', 'budget-released', 'budget-consumed',
] as const;
export type LedgerEvent = typeof EVENTS[number];
