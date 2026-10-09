import type { Channel } from '../src/lnd/types.ts';
import { formatMsat, satToMsat } from '../src/util/money.ts';
import { bitcoinCli, lncli, mine } from '../lab/compose.ts';
import { command, fact, say, step, Verdict, waitUntil } from '../lab/narrate.ts';
import { createInvoice, lndPayments, payArgs, scenario, withPayer } from './lib/lab.ts';
import { describeEvent, runService } from './lib/service.ts';

/**
 * Scenario 3: the merchant owes a refund. Its wallet has on-chain funds and its
 * channel to the router has ample capacity, but setup put that channel's
 * balance on the router's side, so the merchant can receive and cannot send.
 * The refund fails; the lab diagnoses it from the merchant's own view; the
 * operator moves on-chain funds into a new channel; the same refund invoice
 * is paid on retry.
 *
 * The refund amount is computed from the merchant's current channel balances
 * (sendable + 25,000 sat), so the failure is deterministic even after other
 * scenarios have moved money to the merchant.
 */

const MARGIN_SAT = 25_000n;
const MIN_REFUND_SAT = 50_000n;
const NEW_CHANNEL_EXTRA_SAT = 100_000n;

const sendable = (channels: Channel[]): bigint => channels.filter(item => item.active)
  .reduce((sum, item) => sum + (item.localBalanceSat > item.localReserveSat ? item.localBalanceSat - item.localReserveSat : 0n), 0n);

await scenario('Scenario 3: directional liquidity',
  'A refund fails although the merchant has on-chain funds and channel capacity; the lab explains why, fixes it and retries.',
  async context => {
    const verdict = new Verdict('scenario 3');
    const { manifest } = context.lab;
    const refundId = `RFD-3-${context.tag}`;
    const operationId = `REFUND-${refundId}`;

    step('Merchant liquidity before the refund (merchant read-only credential)');
    const merchantChannels = await context.read.merchant.listChannels();
    const wallet = await context.read.merchant.walletBalance();
    const merchantSendable = sendable(merchantChannels);
    const capacity = merchantChannels.reduce((sum, item) => sum + item.capacitySat, 0n);
    let amountSat = merchantSendable + MARGIN_SAT;
    if (amountSat < MIN_REFUND_SAT) amountSat = MIN_REFUND_SAT;
    amountSat = ((amountSat + 999n) / 1000n) * 1000n;
    const amountMsat = satToMsat(amountSat);
    fact('on-chain confirmed', formatMsat(satToMsat(wallet.confirmedSat)));
    fact('channel capacity', formatMsat(satToMsat(capacity)));
    fact('sendable from channels', formatMsat(satToMsat(merchantSendable)));
    fact('refund amount', `${formatMsat(amountMsat)} (sendable + ${MARGIN_SAT} sat, rounded up)`);

    step('Lab precondition, checked with the router\'s read-only credential (a real sender cannot see this)');
    const routerToCustomer = sendable((await context.read.router.listChannels()).filter(item => item.remotePubkey === manifest.nodes.customer.pubkey));
    const newChannelSat = amountSat + NEW_CHANNEL_EXTRA_SAT;
    fact('router outbound toward the customer', formatMsat(satToMsat(routerToCustomer)));
    if (routerToCustomer < amountSat + 10_000n || wallet.confirmedSat < newChannelSat + 50_000n) {
      throw new Error('this lab no longer has the liquidity for scenario 3 (router outbound toward the customer, or merchant on-chain funds); '
        + 'run teardown and setup for a fresh lab');
    }

    step(`Customer issues a refund invoice ${refundId} for ${formatMsat(amountMsat)}`);
    const invoice = await createInvoice('customer', refundId, amountMsat, false);
    const feeLimitMsat = amountMsat / 100n + 1_000_000n;

    step(`Merchant refund worker pays it (operation ${operationId})`);
    const first = await runService(payArgs('merchant-refunds', operationId, 'refund', invoice.paymentRequest, feeLimitMsat), { echo: describeEvent });
    fact('worker exit', `${first.code} (1 = LND reported the payment failed)`);
    const failedLnd = await lndPayments(context, 'merchant', invoice.paymentHash);
    const failedPayment = failedLnd.payments[0];
    const rejectedUpfront = failedLnd.complete && failedLnd.payments.length === 0
      && withPayer(context, 'merchant-refunds', store => store.payment(invoice.paymentHash)?.failureReason?.startsWith('REJECTED_BEFORE_INITIATION') === true);
    verdict.check('the refund failed, as LND reports it', first.code === 1 && (failedPayment?.status === 'FAILED' || rejectedUpfront),
      failedPayment === undefined
        ? `exit ${first.code}; LND refused SendPaymentV2 and holds no payment for the hash`
        : `exit ${first.code}; LND status ${failedPayment.status}, reason ${failedPayment.failureReason}, ${failedPayment.htlcs.length} HTLC attempt(s)`);

    step('Diagnosis from the merchant\'s own view (read-only credential)');
    const diagnosis = await runService(['analysis', 'diagnose', '--node', 'merchant', '--payer', 'merchant-refunds', '--operation', operationId]);
    const report = diagnosis.events.find(item => item.event === 'diagnosis');
    const findings = Array.isArray(report?.findings) ? report.findings.map(String) : [];
    for (const line of findings) say(line);
    const totals = (report?.totals ?? {}) as Record<string, unknown>;
    const onChain = (report?.onChain ?? {}) as Record<string, unknown>;
    const diagnosedSendable = BigInt(String(totals.sendableSat ?? '0'));
    const diagnosedOnChain = BigInt(String(onChain.confirmedSat ?? '0'));
    verdict.check('diagnosis: on-chain funds cover the refund, channel balance does not',
      diagnosedOnChain >= amountSat && diagnosedSendable < amountSat,
      `on-chain ${formatMsat(satToMsat(diagnosedOnChain))}, sendable ${formatMsat(satToMsat(diagnosedSendable))}, refund ${formatMsat(amountMsat)}`);
    verdict.check('diagnosis: capacity exceeds the refund, directional balance does not',
      BigInt(String(totals.capacitySat ?? '0')) >= amountSat && diagnosedSendable < amountSat,
      `capacity ${formatMsat(satToMsat(BigInt(String(totals.capacitySat ?? '0'))))}`);
    const afterFailure = withPayer(context, 'merchant-refunds', store => ({ payment: store.payment(invoice.paymentHash),
      operation: store.operation(operationId), ledger: store.ledger(operationId) }));
    verdict.check('record and operation failed, nothing posted', afterFailure.payment?.state === 'failed'
      && afterFailure.operation?.state === 'failed' && afterFailure.ledger.length === 0,
      `record ${afterFailure.payment?.state ?? 'missing'} (${afterFailure.payment?.failureReason ?? ''}), operation ${afterFailure.operation?.state ?? 'missing'}`);

    step(`Operator fix: move ${formatMsat(satToMsat(newChannelSat))} of on-chain funds into a new channel merchant -> router`);
    say('Channel management needs the node operator\'s authority; the refund worker\'s pay-only credential cannot open channels.');
    const channelsBefore = merchantChannels.length;
    command(`lncli openchannel --node_key <router> --local_amt ${newChannelSat} --sat_per_vbyte 2   # on merchant`);
    await lncli('merchant', ['openchannel', '--node_key', manifest.nodes.router.pubkey, '--local_amt', newChannelSat.toString(), '--sat_per_vbyte', '2']);
    await waitUntil('the funding transaction in the mempool', async () => {
      const info = JSON.parse(await bitcoinCli(['getmempoolinfo'], false)) as { size?: number };
      return (info.size ?? 0) >= 1 ? true : undefined;
    }, { timeoutMs: 60_000 });
    const height = await mine(6);
    fact('mined to height', height);
    await waitUntil('the new channel to be active on the merchant', async () => {
      const list = await context.read.merchant.listChannels();
      return list.filter(item => item.active).length > channelsBefore && sendable(list) >= amountSat ? true : undefined;
    }, { timeoutMs: 120_000 });
    fact('sendable from channels now', formatMsat(satToMsat(sendable(await context.read.merchant.listChannels()))));

    step('Retry the same refund: the same invoice and payment hash, allowed because LND reported the first attempt failed');
    const retry = await runService(['payer', 'retry', '--as', 'merchant-refunds', '--operation', operationId], { echo: describeEvent });

    step('Verdict from node state and durable records');
    const lnd = await lndPayments(context, 'merchant', invoice.paymentHash);
    const succeeded = lnd.payments.filter(item => item.status === 'SUCCEEDED');
    const customerInvoice = await context.read.customer.lookupInvoice(invoice.paymentHash);
    const after = withPayer(context, 'merchant-refunds', store => ({ payment: store.payment(invoice.paymentHash),
      operation: store.operation(operationId), ledger: store.ledger(operationId) }));
    verdict.check('the retried refund succeeded', retry.code === 0 && succeeded.length === 1 && lnd.complete,
      `retry exit ${retry.code}; LND payments for the hash: ${lnd.payments.map(item => item.status).join(', ') || 'none'}`);
    verdict.check('the customer received the refund once, in full', customerInvoice.state === 'SETTLED' && customerInvoice.amtPaidMsat === amountMsat,
      `customer invoice ${customerInvoice.state}, paid ${formatMsat(customerInvoice.amtPaidMsat)}`);
    verdict.check('record shows two submissions of one payment and the actual fee',
      after.payment?.state === 'succeeded' && after.payment.submissions === 2 && after.payment.feeMsat === succeeded[0]?.feeMsat,
      `submissions ${after.payment?.submissions ?? 'none'}, fee ${formatMsat(after.payment?.feeMsat ?? 0n)} / LND ${formatMsat(succeeded[0]?.feeMsat ?? 0n)}`);
    verdict.check('refund operation completed and posted once', after.operation?.state === 'completed'
      && after.ledger.filter(item => item.account === 'principal').length === 1
      && after.ledger.find(item => item.account === 'principal')?.amountMsat === amountMsat,
      `operation ${after.operation?.state ?? 'missing'}, ${after.ledger.length} ledger entries`);
    return verdict;
  });
