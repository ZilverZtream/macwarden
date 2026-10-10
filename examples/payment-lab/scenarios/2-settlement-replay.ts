import { formatMsat } from '../src/util/money.ts';
import { fact, say, step, Verdict, waitUntil } from '../lab/narrate.ts';
import { createInvoice, payArgs, scenario, withReceiver } from './lib/lab.ts';
import { describeEvent, runService, ServiceProcess } from './lib/service.ts';

/**
 * Scenario 2: LND delivers a settlement again after the merchant's listener
 * restarts. The order must be fulfilled and the sale posted once, proven from
 * the merchant's durable records, while the delivery log shows the repeats.
 *
 * The listener commits each effect and its cursor in one transaction, so a
 * plain crash does not repeat a delivery. Repeats still happen whenever a
 * listener starts from an older cursor than its effects: the cursor kept in
 * another store, a second instance, a restored cursor, or a replay after an
 * incident. The scenario starts the second listener from the cursor as it was
 * after the first order, and LND replays every settlement after it.
 */

const AMOUNT_A_MSAT = 10_000_000n;
const AMOUNT_B_MSAT = 12_000_000n;
const FEE_LIMIT_MSAT = 1_000_000n;

await scenario('Scenario 2: settlement notification repeats after a restart',
  'Two orders are paid while the merchant listener runs; a restarted listener receives the second settlement again.',
  async context => {
    const verdict = new Verdict('scenario 2');
    const orderA = `ORD-2A-${context.tag}`;
    const orderB = `ORD-2B-${context.tag}`;

    step('Start the merchant settlement listener (SubscribeInvoices from its stored cursor)');
    const first = new ServiceProcess(['receiver', 'listen', '--as', 'merchant', '--reconcile-interval-s', '5'], { echo: describeEvent });
    await first.waitForEvent('the listener to subscribe', event => event.event === 'subscribing', 30_000);

    step(`Create and pay order ${orderA} (${formatMsat(AMOUNT_A_MSAT)})`);
    const invoiceA = await createInvoice('merchant', orderA, AMOUNT_A_MSAT, false);
    const payA = await runService(payArgs('customer-payer', `PAY-${orderA}`, 'order-payment', invoiceA.paymentRequest, FEE_LIMIT_MSAT),
      { echo: describeEvent });
    if (payA.code !== 0) throw new Error(`payment for ${orderA} did not succeed (exit ${payA.code})`);
    await waitUntil(`order ${orderA} fulfilled by the listener`, () =>
      withReceiver(context, 'merchant', store => (store.order(orderA)?.state === 'fulfilled' ? true : undefined)), { timeoutMs: 60_000 });
    const settleIndexA = withReceiver(context, 'merchant', store => store.invoice(invoiceA.paymentHash)?.settleIndex);
    if (settleIndexA === undefined) throw new Error('order A has no settle index');
    fact(`settle index of ${orderA}`, settleIndexA);

    step(`Create and pay order ${orderB} (${formatMsat(AMOUNT_B_MSAT)})`);
    const invoiceB = await createInvoice('merchant', orderB, AMOUNT_B_MSAT, false);
    const payB = await runService(payArgs('customer-payer', `PAY-${orderB}`, 'order-payment', invoiceB.paymentRequest, FEE_LIMIT_MSAT),
      { echo: describeEvent });
    if (payB.code !== 0) throw new Error(`payment for ${orderB} did not succeed (exit ${payB.code})`);
    await waitUntil(`order ${orderB} fulfilled by the listener`, () =>
      withReceiver(context, 'merchant', store => (store.order(orderB)?.state === 'fulfilled' ? true : undefined)), { timeoutMs: 60_000 });

    step('Stop the listener');
    await first.stop();
    const beforeRestart = withReceiver(context, 'merchant', store => ({
      settled: store.deliveries(invoiceB.paymentHash).filter(item => item.lndState === 'SETTLED').length,
      cursor: store.cursor(),
    }));
    fact(`settled deliveries of ${orderB} so far`, beforeRestart.settled);
    fact('stored cursor (settle index)', beforeRestart.cursor.settleIndex);

    step(`Restart the listener from an older cursor: settle index ${settleIndexA}, as it was after ${orderA}`);
    say('Simulates a listener whose cursor is behind its effects (cursor in another store, a second instance, a restored cursor).');
    await runService(['receiver', 'cursor-set', '--as', 'merchant', '--settle-index', settleIndexA.toString()], { echo: describeEvent });
    const restartedAt = new Date().toISOString();
    const second = new ServiceProcess(['receiver', 'listen', '--as', 'merchant', '--reconcile-interval-s', '5'], { echo: describeEvent });
    await second.waitForEvent(`LND to deliver the settlement of ${orderB} again`, event => event.event === 'invoice-delivery'
      && event.source === 'subscription' && event.paymentHash === invoiceB.paymentHash && event.lndState === 'SETTLED', 60_000);
    await second.stop();

    step('A reconciliation pass looks the invoice up as well (a third path to the same settlement)');
    await runService(['receiver', 'reconcile', '--as', 'merchant', '--order', orderB], { echo: describeEvent });

    step('Verdict from the merchant\'s durable records and LND');
    const records = withReceiver(context, 'merchant', store => ({
      deliveries: store.deliveries(invoiceB.paymentHash),
      fulfillments: store.fulfillmentCount(orderB),
      ledger: store.ledger(orderB),
      order: store.order(orderB),
      cursor: store.cursor(),
    }));
    const lnd = await context.read.merchant.lookupInvoice(invoiceB.paymentHash);
    const settledDeliveries = records.deliveries.filter(item => item.lndState === 'SETTLED');
    const replayed = records.deliveries.filter(item => item.source === 'subscription' && item.lndState === 'SETTLED'
      && item.receivedAt >= restartedAt);
    for (const item of records.deliveries) say(`delivery ${item.receivedAt} via ${item.source}: ${item.lndState} -> ${item.outcome}`);
    verdict.check('the settlement was delivered more than once', settledDeliveries.length >= 2,
      `${settledDeliveries.length} SETTLED deliveries (${settledDeliveries.map(item => item.source).join(', ')})`);
    verdict.check('the restarted listener received it again from LND', replayed.length >= 1 && settledDeliveries.some(item => item.outcome === 'duplicate'),
      `${replayed.length} subscription redelivery(ies); outcomes ${settledDeliveries.map(item => item.outcome).join(', ')}`);
    verdict.check('order fulfilled exactly once', records.order?.state === 'fulfilled' && records.fulfillments === 1
      && settledDeliveries.filter(item => item.outcome === 'fulfilled').length === 1,
      `order ${records.order?.state ?? 'missing'}, ${records.fulfillments} fulfillment row(s)`);
    verdict.check('sale posted exactly once, for the amount LND received', records.ledger.length === 1
      && records.ledger[0]?.amountMsat === lnd.amtPaidMsat && lnd.state === 'SETTLED',
      `${records.ledger.length} ledger entr${records.ledger.length === 1 ? 'y' : 'ies'} of ${formatMsat(records.ledger[0]?.amountMsat ?? 0n)}; `
      + `LND: ${lnd.state}, paid ${formatMsat(lnd.amtPaidMsat)}`);
    verdict.check('cursor caught up with the replayed settlement', records.cursor.settleIndex >= lnd.settleIndex,
      `cursor ${records.cursor.settleIndex}, invoice settle index ${lnd.settleIndex}`);
    return verdict;
  });
