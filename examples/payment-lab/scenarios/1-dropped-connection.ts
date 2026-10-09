import { parseArgs } from 'node:util';
import { UNRESOLVED_STATES } from '../src/payer/store.ts';
import { formatMsat } from '../src/util/money.ts';
import { fact, say, step, Verdict, waitUntil } from '../lab/narrate.ts';
import { cancelIfOpen, createInvoice, lndPayments, payArgs, scenario, withPayer, withReceiver } from './lib/lab.ts';
import { describeEvent, runService, ServiceProcess } from './lib/service.ts';

/**
 * Scenario 1: the connection is cut after submission, while the merchant holds
 * the HTLC. The record must stay unresolved (never failed), recovery must go
 * through TrackPaymentV2, and the business operation must complete exactly
 * once with the real routing fee, with one payment and one submission.
 *
 * --cut kill (default): the worker process is killed (SIGKILL / TerminateProcess).
 * --cut drop: the worker destroys its HTTP connection to LND and stays alive.
 */

const { values } = parseArgs({ options: { cut: { type: 'string', default: 'kill' } }, strict: true });
const cut = values.cut;
if (cut !== 'kill' && cut !== 'drop') {
  process.stderr.write('usage: 1-dropped-connection [--cut kill|drop]\n');
  process.exit(2);
}

const AMOUNT_MSAT = 25_000_000n;
const FEE_LIMIT_MSAT = 1_000_000n;

await scenario('Scenario 1: dropped connection after submission',
  'A hold invoice keeps the payment in flight; the payer loses its connection; recovery goes through TrackPaymentV2.',
  async context => {
    const verdict = new Verdict('scenario 1');
    const orderId = `ORD-1-${context.tag}`;
    const operationId = `PAY-${orderId}`;

    step(`Merchant creates a hold invoice for order ${orderId} (${formatMsat(AMOUNT_MSAT)})`);
    say('The merchant generates the preimage and stores it before calling AddHoldInvoice, so LND will hold any HTLC until the merchant releases it.');
    const invoice = await createInvoice('merchant', orderId, AMOUNT_MSAT, true);
    context.onAbort(() => cancelIfOpen('merchant', orderId));
    fact('payment hash', invoice.paymentHash);

    step(`Customer worker records operation ${operationId} and the payment hash, then calls SendPaymentV2`);
    const worker = new ServiceProcess(payArgs('customer-payer', operationId, 'order-payment', invoice.paymentRequest, FEE_LIMIT_MSAT,
      cut === 'drop' ? ['--fault', 'drop-stream-after-in-flight'] : []), { echo: describeEvent });
    await worker.waitForEvent('an in-flight update with a held HTLC',
      event => event.event === 'payment-update' && Number(event.attemptsInFlight) > 0, 60_000);
    await waitUntil('the merchant node to report the HTLC accepted', async () =>
      (await context.read.merchant.lookupInvoice(invoice.paymentHash)).state === 'ACCEPTED' ? true : undefined, { timeoutMs: 60_000 });
    say('The merchant node holds the HTLC (invoice state ACCEPTED). Nothing will settle or fail until the merchant decides.');

    step(cut === 'kill' ? 'Kill the worker process while the HTLC is held' : 'Drop the worker\'s HTTP connection while the HTLC is held');
    const exitCode = cut === 'kill' ? await worker.kill() : await worker.finished(60_000, 'the worker after the dropped connection');
    fact('worker exit', exitCode);
    const before = withPayer(context, 'customer-payer', store => ({
      payment: store.payment(invoice.paymentHash), operation: store.operation(operationId), ledger: store.ledger(operationId),
    }));
    fact('record state', before.payment?.state ?? 'missing');
    fact('operation state', before.operation?.state ?? 'missing');
    verdict.check('record is unresolved after the cut, not failed',
      before.payment !== undefined && UNRESOLVED_STATES.includes(before.payment.state),
      `state ${before.payment?.state ?? 'missing'} (the last thing this worker knew; ${cut === 'drop' ? 'it marked the loss itself' : 'it had no chance to write anything'})`);
    verdict.check('business operation still open, nothing posted', before.operation?.state === 'open' && before.ledger.length === 0,
      `operation ${before.operation?.state ?? 'missing'}, ${before.ledger.length} ledger entries`);
    const lndDuring = await lndPayments(context, 'customer', invoice.paymentHash);
    verdict.check('LND still holds the payment in flight', lndDuring.payments.length === 1 && lndDuring.payments[0]?.status === 'IN_FLIGHT',
      `${lndDuring.payments.length} payment(s) for the hash, status ${lndDuring.payments[0]?.status ?? 'none'}`);

    step('Merchant tries to issue a replacement invoice for the same order');
    const replacement = await runService(['receiver', 'create-invoice', '--as', 'merchant', '--order', orderId, '--amount-msat',
      AMOUNT_MSAT.toString(), '--hold'], { echo: describeEvent });
    verdict.check('no replacement invoice while the first is unresolved', replacement.code === 3,
      `create-invoice exit ${replacement.code} (3 = refused by the one-live-invoice-per-order constraint)`);

    step('Restart: a new process reconciles the record with TrackPaymentV2 (it never calls SendPaymentV2)');
    const reconciler = new ServiceProcess(['payer', 'reconcile', '--as', 'customer-payer', '--payment-hash', invoice.paymentHash,
      '--timeout-s', '300'], { echo: describeEvent });
    await reconciler.waitForEvent('TrackPaymentV2 to report the payment in flight',
      event => event.event === 'payment-update' && event.source === 'TrackPaymentV2' && event.status === 'IN_FLIGHT', 60_000);

    step('Merchant settles the hold invoice with its stored preimage');
    const settled = await runService(['receiver', 'settle', '--as', 'merchant', '--order', orderId], { echo: describeEvent });
    verdict.check('merchant settled the hold invoice', settled.code === 0, `settle exit ${settled.code}`);
    const reconciled = await reconciler.finished(120_000, 'the reconciler');
    verdict.check('reconciler reached a terminal state', reconciled === 0, `reconcile exit ${reconciled} (0 = succeeded)`);

    step('A client repeats the original request for the same operation');
    const repeat = await runService(payArgs('customer-payer', operationId, 'order-payment', invoice.paymentRequest, FEE_LIMIT_MSAT),
      { echo: describeEvent });
    verdict.check('repeat is answered from the record, not paid again',
      repeat.code === 0 && !repeat.events.some(event => event.event === 'submitted'),
      `exit ${repeat.code}, SendPaymentV2 calls in the repeat: ${repeat.events.filter(event => event.event === 'submitted').length}`);

    step('Merchant reconciles its order from the invoice state');
    await runService(['receiver', 'reconcile', '--as', 'merchant', '--order', orderId], { echo: describeEvent });

    step('Verdict from node state and durable records');
    const lnd = await lndPayments(context, 'customer', invoice.paymentHash);
    const payment = lnd.payments[0];
    const after = withPayer(context, 'customer-payer', store => ({
      payment: store.payment(invoice.paymentHash), operation: store.operation(operationId), ledger: store.ledger(operationId),
      completions: store.events(invoice.paymentHash).filter(item => item.kind === 'succeeded').length,
    }));
    const merchant = withReceiver(context, 'merchant', store => ({
      invoices: store.invoicesForOrder(orderId).length, fulfillments: store.fulfillmentCount(orderId), ledger: store.ledger(orderId),
    }));
    const merchantInvoice = await context.read.merchant.lookupInvoice(invoice.paymentHash);
    verdict.check('exactly one payment for the hash on the customer node', lnd.complete && lnd.payments.length === 1,
      `ListPayments: ${lnd.payments.length} payment(s)${lnd.complete ? '' : ' (scan incomplete)'}`);
    verdict.check('LND reports it succeeded', payment?.status === 'SUCCEEDED', `status ${payment?.status ?? 'none'}`);
    verdict.check('one SendPaymentV2 call in total', after.payment?.submissions === 1, `submissions recorded: ${after.payment?.submissions ?? 'none'}`);
    verdict.check('record matches LND: principal and routing fee',
      after.payment?.state === 'succeeded' && after.payment.valueMsat === payment?.valueMsat && after.payment.feeMsat === payment?.feeMsat,
      `record ${after.payment?.state ?? 'missing'}, value ${formatMsat(after.payment?.valueMsat ?? 0n)} / LND ${formatMsat(payment?.valueMsat ?? 0n)}, `
      + `fee ${formatMsat(after.payment?.feeMsat ?? 0n)} / LND ${formatMsat(payment?.feeMsat ?? 0n)}`);
    const principal = after.ledger.find(item => item.account === 'principal');
    const fee = after.ledger.find(item => item.account === 'routing-fee');
    verdict.check('operation completed exactly once, ledger posted once',
      after.operation?.state === 'completed' && after.completions === 1 && after.ledger.length === 2
      && principal?.amountMsat === payment?.valueMsat && fee?.amountMsat === payment?.feeMsat,
      `operation ${after.operation?.state ?? 'missing'}, completion events ${after.completions}, ledger entries ${after.ledger.length}`);
    verdict.check('merchant: one invoice, settled for the full amount, order fulfilled once',
      merchant.invoices === 1 && merchantInvoice.state === 'SETTLED' && merchantInvoice.amtPaidMsat === AMOUNT_MSAT
      && merchant.fulfillments === 1 && merchant.ledger.length === 1,
      `${merchant.invoices} invoice(s), LND state ${merchantInvoice.state}, paid ${formatMsat(merchantInvoice.amtPaidMsat)}, `
      + `${merchant.fulfillments} fulfillment(s), ${merchant.ledger.length} sales entr${merchant.ledger.length === 1 ? 'y' : 'ies'}`);
    return verdict;
  });
