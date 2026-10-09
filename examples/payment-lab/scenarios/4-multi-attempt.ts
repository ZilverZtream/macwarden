import { forwardsSince } from '../src/analysis/payments.ts';
import { formatMsat, satToMsat } from '../src/util/money.ts';
import { fact, say, step, Verdict, waitUntil } from '../lab/narrate.ts';
import { createInvoice, lndPayments, payArgs, scenario, withPayer, withReceiver } from './lib/lab.ts';
import { describeEvent, runService } from './lib/service.ts';

/**
 * Scenario 4: a payment that settles over several HTLC attempts. The amount is
 * chosen above the local balance of every single customer channel (A and B),
 * so LND must split it (multi-part payment) and may retry shards. The
 * accounting must show one principal and the routing fees actually paid,
 * summed from the successful HTLC attempts, matching LND exactly, and the
 * router's own forwarding log and fee policy must agree.
 */

const MARGIN_SAT = 20_000n;

await scenario('Scenario 4: multi-attempt settlement',
  'One payment, several HTLC attempts over two channels; the books show one principal and the real total fee.',
  async context => {
    const verdict = new Verdict('scenario 4');
    const { manifest } = context.lab;
    const orderId = `ORD-4-${context.tag}`;
    const operationId = `PAY-${orderId}`;

    step('Customer channel balances (customer read-only credential)');
    const toRouter = (await context.read.customer.listChannels())
      .filter(item => item.active && item.initiator && item.remotePubkey === manifest.nodes.router.pubkey);
    for (const channel of toRouter) fact(`channel ${channel.chanId} local`, formatMsat(satToMsat(channel.localBalanceSat)));
    const largestLocal = toRouter.reduce((max, item) => (item.localBalanceSat > max ? item.localBalanceSat : max), 0n);
    const totalSendable = toRouter.reduce((sum, item) => sum + (item.localBalanceSat > item.localReserveSat
      ? item.localBalanceSat - item.localReserveSat : 0n), 0n);
    const amountSat = ((largestLocal + MARGIN_SAT + 999n) / 1000n) * 1000n;
    const amountMsat = satToMsat(amountSat);
    const feeLimitMsat = amountMsat / 100n + 10_000_000n;
    fact('payment amount', `${formatMsat(amountMsat)} (above the largest single channel balance, ${formatMsat(satToMsat(largestLocal))})`);

    const routerToMerchant = (await context.read.router.listChannels()).find(item => item.chanId === manifest.channels.routerMerchant);
    if (toRouter.length < 2 || totalSendable < amountSat + feeLimitMsat / 1000n + 10_000n
      || routerToMerchant === undefined || routerToMerchant.localBalanceSat - routerToMerchant.localReserveSat < amountSat + 10_000n) {
      throw new Error('this lab no longer has the liquidity for scenario 4 (customer channels A and B, or router -> merchant); '
        + 'run teardown and setup for a fresh lab');
    }

    step(`Merchant creates an invoice for order ${orderId}`);
    const invoice = await createInvoice('merchant', orderId, amountMsat, false);

    step('Customer pays it with up to 16 parts');
    const paid = await runService(payArgs('customer-payer', operationId, 'order-payment', invoice.paymentRequest, feeLimitMsat,
      ['--max-parts', '16']), { echo: describeEvent });
    fact('worker exit', paid.code);
    const updates = paid.events.filter(item => item.event === 'payment-update').length;
    fact('SendPaymentV2 updates received', updates);

    step('Merchant reconciles its order from the invoice state');
    await runService(['receiver', 'reconcile', '--as', 'merchant', '--order', orderId], { echo: describeEvent });

    step('Verdict: the books against LND, the router\'s forwarding log and its fee policy');
    const lnd = await lndPayments(context, 'customer', invoice.paymentHash);
    const payment = lnd.payments[0];
    const shards = payment?.htlcs.filter(item => item.status === 'SUCCEEDED') ?? [];
    const failedAttempts = payment?.htlcs.filter(item => item.status === 'FAILED') ?? [];
    for (const attempt of payment?.htlcs ?? []) {
      say(`attempt ${attempt.attemptId}: ${attempt.status}, ${formatMsat(attempt.principalMsat)} over ${attempt.route.hops.map(hop => hop.chanId).join(' > ')}, `
        + `fee ${formatMsat(attempt.route.totalFeesMsat)}${attempt.failureCode === undefined ? '' : `, ${attempt.failureCode} at hop ${attempt.failureSourceIndex}`}`);
    }
    const shardPrincipal = shards.reduce((sum, item) => sum + item.principalMsat, 0n);
    const shardFees = shards.reduce((sum, item) => sum + item.route.totalFeesMsat, 0n);
    const record = withPayer(context, 'customer-payer', store => ({ payment: store.payment(invoice.paymentHash),
      attempts: store.attempts(invoice.paymentHash), ledger: store.ledger(operationId), operation: store.operation(operationId) }));
    const principal = record.ledger.filter(item => item.account === 'principal');
    const fees = record.ledger.filter(item => item.account === 'routing-fee');

    verdict.check('payment succeeded over several HTLC attempts', paid.code === 0 && payment?.status === 'SUCCEEDED' && shards.length >= 2,
      `status ${payment?.status ?? 'none'}; ${payment?.htlcs.length ?? 0} attempts: ${shards.length} succeeded, ${failedAttempts.length} failed`);
    verdict.check('one payment for the hash', lnd.complete && lnd.payments.length === 1, `ListPayments: ${lnd.payments.length}`);
    verdict.check('principal: the shards add up to the invoice amount', payment?.valueMsat === amountMsat && shardPrincipal === amountMsat,
      `LND value ${formatMsat(payment?.valueMsat ?? 0n)}, sum of successful shards ${formatMsat(shardPrincipal)}, invoice ${formatMsat(amountMsat)}`);
    verdict.check('fee: LND\'s total equals the fees of the successful attempts', payment?.feeMsat === shardFees,
      `LND fee ${formatMsat(payment?.feeMsat ?? 0n)}, sum over successful attempts ${formatMsat(shardFees)}`);
    verdict.check('books: one principal entry and one fee entry, equal to LND',
      principal.length === 1 && fees.length === 1 && principal[0]?.amountMsat === payment?.valueMsat && fees[0]?.amountMsat === payment?.feeMsat
      && record.operation?.state === 'completed',
      `principal ${formatMsat(principal[0]?.amountMsat ?? 0n)}, fee ${formatMsat(fees[0]?.amountMsat ?? 0n)}, operation ${record.operation?.state ?? 'missing'}`);
    verdict.check('stored attempts match LND\'s attempts', record.attempts.length === (payment?.htlcs.length ?? -1)
      && record.attempts.every(stored => payment?.htlcs.some(item => item.attemptId === stored.attemptId && item.status === stored.status)),
      `${record.attempts.length} stored, ${payment?.htlcs.length ?? 0} in LND`);
    const base = BigInt(manifest.routerPolicy.baseFeeMsat);
    const ppm = BigInt(manifest.routerPolicy.feeRatePpm);
    const policyFee = shards.reduce((sum, item) => sum + base + (item.principalMsat * ppm) / 1_000_000n, 0n);
    verdict.check('fee equals the router\'s policy applied per shard', policyFee === payment?.feeMsat,
      `${shards.length} x ${base} msat base + ${ppm} ppm of each shard = ${formatMsat(policyFee)}`);
    if (payment !== undefined) {
      // LND writes forwarding events in batches (every few seconds), so the log is polled until every shard appears.
      const matchForwards = async (): Promise<{ complete: boolean; matched: number; routerFees: bigint }> => {
        const forwards = await forwardsSince(context.read.router, payment.creationTimeNs / 1_000_000_000n - 1n);
        const candidates = forwards.events.filter(item => item.chanIdOut === manifest.channels.routerMerchant && item.timestampNs >= payment.creationTimeNs);
        let routerFees = 0n;
        let matched = 0;
        const used = new Set<number>();
        for (const shard of shards) {
          const index = candidates.findIndex((item, position) => !used.has(position) && item.amtOutMsat === shard.principalMsat);
          if (index === -1) continue;
          used.add(index);
          matched += 1;
          routerFees += candidates[index]?.feeMsat ?? 0n;
        }
        return { complete: forwards.complete, matched, routerFees };
      };
      let observed = { complete: false, matched: 0, routerFees: 0n };
      try {
        observed = await waitUntil('the router\'s forwarding log to show every shard', async () => {
          const result = await matchForwards();
          observed = result;
          return result.matched === shards.length ? result : undefined;
        }, { timeoutMs: 60_000, intervalMs: 2000 });
      } catch (error) {
        say(error instanceof Error ? error.message : String(error));
      }
      verdict.check('the router\'s forwarding log shows the same fees',
        observed.complete && observed.matched === shards.length && observed.routerFees === payment.feeMsat,
        `${observed.matched}/${shards.length} shards found in ForwardingHistory, router earned ${formatMsat(observed.routerFees)}`);
    }
    const merchantInvoice = await context.read.merchant.lookupInvoice(invoice.paymentHash);
    const merchant = withReceiver(context, 'merchant', store => ({ fulfillments: store.fulfillmentCount(orderId), ledger: store.ledger(orderId) }));
    verdict.check('merchant received the amount once, in several HTLCs',
      merchantInvoice.state === 'SETTLED' && merchantInvoice.amtPaidMsat === amountMsat
      && merchantInvoice.htlcs.filter(item => item.state === 'SETTLED').length >= 2 && merchant.fulfillments === 1 && merchant.ledger.length === 1,
      `invoice ${merchantInvoice.state}, paid ${formatMsat(merchantInvoice.amtPaidMsat)} in `
      + `${merchantInvoice.htlcs.filter(item => item.state === 'SETTLED').length} HTLCs, ${merchant.fulfillments} fulfillment(s)`);
    return verdict;
  });
