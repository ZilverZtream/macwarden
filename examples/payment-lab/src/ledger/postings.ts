import { ACCOUNT, budgetAccount, counterAccountFor } from './accounts.ts';
import type { Posting } from './journal.ts';

/**
 * The posting rules: one function per event, each returning a balanced entry. The stores call
 * them inside the transaction of the state change; the 1.3 migration calls them for the rows
 * a 1.2 database already holds (origin `migrated`).
 */

type Origin = Pick<Posting, 'origin' | 'postedAt'>;
export type OperationKind = 'order-payment' | 'refund' | 'payout';

/** Payer: LND reported the payment succeeded. Principal and fee are separate legs, as LND reports them. */
export function paymentSucceeded(input: { operationId: string; kind: OperationKind; paymentHash: string; valueMsat: bigint;
  feeMsat: bigint } & Origin): Posting {
  return { event: 'payment-succeeded', reference: input.paymentHash, operationId: input.operationId, paymentHash: input.paymentHash,
    origin: input.origin, postedAt: input.postedAt, lines: [
      { account: counterAccountFor(input.kind), direction: 'debit', amountMsat: input.valueMsat, leg: 'principal' },
      { account: ACCOUNT.walletOutgoing, direction: 'credit', amountMsat: input.valueMsat },
      { account: ACCOUNT.routingFees, direction: 'debit', amountMsat: input.feeMsat, leg: 'routing-fee' },
      { account: ACCOUNT.walletOutgoing, direction: 'credit', amountMsat: input.feeMsat },
    ] };
}

/** Payer: a second payment of an operation succeeded; its principal moves from the operation's account to suspense. */
export function payerDoublePayment(input: { operationId: string; kind: OperationKind; paymentHash: string; valueMsat: bigint } & Origin): Posting {
  return { event: 'double-payment', reference: input.paymentHash, operationId: input.operationId, paymentHash: input.paymentHash,
    origin: input.origin, postedAt: input.postedAt, lines: [
      { account: ACCOUNT.suspenseDoublePayment, direction: 'debit', amountMsat: input.valueMsat },
      { account: counterAccountFor(input.kind), direction: 'credit', amountMsat: input.valueMsat },
    ] };
}

interface ReservationRef { reservationId: bigint; budgetId: string; operationId: string; paymentHash: string }

/** Payer: a reservation of principal plus fee allowance is held against a budget. */
export function budgetHeld(input: ReservationRef & { amountMsat: bigint } & Origin): Posting {
  return { event: 'budget-held', reference: `reservation:${input.reservationId}`, operationId: input.operationId,
    paymentHash: input.paymentHash, origin: input.origin, postedAt: input.postedAt, lines: [
      { account: budgetAccount(input.budgetId), direction: 'debit', amountMsat: input.amountMsat },
      { account: ACCOUNT.budgetCommitments, direction: 'credit', amountMsat: input.amountMsat },
    ] };
}

/** Payer: a held reservation is released (the payment failed, or was withdrawn): the whole hold returns. */
export function budgetReleased(input: ReservationRef & { amountMsat: bigint } & Origin): Posting {
  return { event: 'budget-released', reference: `reservation:${input.reservationId}`, operationId: input.operationId,
    paymentHash: input.paymentHash, origin: input.origin, postedAt: input.postedAt, lines: [
      { account: ACCOUNT.budgetCommitments, direction: 'debit', amountMsat: input.amountMsat },
      { account: budgetAccount(input.budgetId), direction: 'credit', amountMsat: input.amountMsat },
    ] };
}

/**
 * Payer: a reservation is consumed (LND reported success). The budget's commitment becomes
 * principal plus the actual fee: from a held reservation the entry moves the difference between
 * the allowance held and the fee paid (normally a release of the unused allowance); from a
 * released one (success after a recorded failure) it commits principal plus fee again.
 */
export function budgetConsumed(input: ReservationRef & { fromState: 'held' | 'released'; principalMsat: bigint;
  allowanceMsat: bigint; feeMsat: bigint } & Origin): Posting {
  const budget = budgetAccount(input.budgetId);
  const base = { event: 'budget-consumed' as const, reference: `reservation:${input.reservationId}`, operationId: input.operationId,
    paymentHash: input.paymentHash, origin: input.origin, postedAt: input.postedAt };
  if (input.fromState === 'released') {
    const amount = input.principalMsat + input.feeMsat;
    return { ...base, lines: [
      { account: budget, direction: 'debit', amountMsat: amount },
      { account: ACCOUNT.budgetCommitments, direction: 'credit', amountMsat: amount },
    ] };
  }
  const unused = input.allowanceMsat - input.feeMsat;
  return { ...base, lines: unused >= 0n
    ? [{ account: ACCOUNT.budgetCommitments, direction: 'debit', amountMsat: unused }, { account: budget, direction: 'credit', amountMsat: unused }]
    : [{ account: budget, direction: 'debit', amountMsat: -unused }, { account: ACCOUNT.budgetCommitments, direction: 'credit', amountMsat: -unused }] };
}

/** Receiver: an invoice settled (LND's amt_paid_msat arrived) for an order. */
export function invoiceSettled(input: { orderId: string; paymentHash: string; amtPaidMsat: bigint } & Origin): Posting {
  return { event: 'invoice-settled', reference: input.paymentHash, operationId: input.orderId, paymentHash: input.paymentHash,
    origin: input.origin, postedAt: input.postedAt, lines: [
      { account: ACCOUNT.walletIncoming, direction: 'debit', amountMsat: input.amtPaidMsat, leg: 'sale' },
      { account: ACCOUNT.customerReceivable, direction: 'credit', amountMsat: input.amtPaidMsat },
    ] };
}

/** Receiver: a second invoice of an order fulfilled by another was paid; the money is held in suspense, to be returned. */
export function receiverDoublePayment(input: { orderId: string; paymentHash: string; amtPaidMsat: bigint } & Origin): Posting {
  return { event: 'double-payment', reference: input.paymentHash, operationId: input.orderId, paymentHash: input.paymentHash,
    origin: input.origin, postedAt: input.postedAt, lines: [
      { account: ACCOUNT.customerReceivable, direction: 'debit', amountMsat: input.amtPaidMsat },
      { account: ACCOUNT.suspenseDoublePayment, direction: 'credit', amountMsat: input.amtPaidMsat },
    ] };
}

/** Receiver: LND reports an invoice settled for less than the order's amount; the money arrived, the order is not fulfilled. */
export function underpaidSettlement(input: { orderId: string; paymentHash: string; amtPaidMsat: bigint } & Origin): Posting {
  return { event: 'underpaid-settlement', reference: input.paymentHash, operationId: input.orderId, paymentHash: input.paymentHash,
    origin: input.origin, postedAt: input.postedAt, lines: [
      { account: ACCOUNT.walletIncoming, direction: 'debit', amountMsat: input.amtPaidMsat },
      { account: ACCOUNT.suspenseDoublePayment, direction: 'credit', amountMsat: input.amtPaidMsat },
    ] };
}
