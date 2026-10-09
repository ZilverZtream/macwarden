import type { BudgetStatus } from '../src/payer/store.ts';
import { formatMsat, satToMsat } from '../src/util/money.ts';
import { fact, say, step, Verdict, waitUntil } from '../lab/narrate.ts';
import { cancelIfOpen, createInvoice, lndPayments, payArgs, scenario, withPayer } from './lib/lab.ts';
import { describeEvent, runService, ServiceProcess, type ServiceEvent } from './lib/service.ts';

/**
 * Scenario 5: two payouts that each fit the remaining budget but not together
 * are started at the same instant by two processes. The reservation of
 * principal plus fee allowance is taken atomically (one SQLite write
 * transaction), so exactly one is admitted. A reservation stays held while its
 * payment is unresolved, is released when LND reports a failure, and is
 * reduced to principal plus the actual fee when LND reports success.
 */

const LIMIT_SAT = 100_000n;
const PAYOUT_SAT = 60_000n;
const SMALL_SAT = 10_000n;
const NEAR_LIMIT_SAT = 38_500n;
const ALLOWANCE_MSAT = 1_000_000n;

const admitted = (event: ServiceEvent): boolean => event.event === 'payment-update' && Number(event.attemptsInFlight) > 0;
const refused = (event: ServiceEvent): boolean => event.event === 'intent-refused';

await scenario('Scenario 5: concurrent budget enforcement',
  'Two concurrent payouts race for one budget; reservations hold while a payment is unresolved and settle to the actual fee.',
  async context => {
    const verdict = new Verdict('scenario 5');
    const budgetId = `PAYOUTS-5-${context.tag}`;
    const ids = { p1: `PO-5-1-${context.tag}`, p2: `PO-5-2-${context.tag}`, small: `PO-5-3-${context.tag}`, near: `PO-5-4-${context.tag}` };
    const budget = (): BudgetStatus => {
      const status = withPayer(context, 'customer-payer', store => store.budgetStatus(budgetId));
      if (status === undefined) throw new Error(`budget ${budgetId} is missing`);
      return status;
    };
    const showBudget = (label: string): BudgetStatus => {
      const status = budget();
      say(`budget ${label}: limit ${formatMsat(status.limitMsat)}, held ${formatMsat(status.heldMsat)}, `
        + `consumed ${formatMsat(status.consumedMsat)}, available ${formatMsat(status.availableMsat)}`);
      return status;
    };

    step(`Set payout budget ${budgetId} to ${formatMsat(satToMsat(LIMIT_SAT))}`);
    await runService(['payer', 'budget-set', '--as', 'customer-payer', '--budget', budgetId, '--limit-msat', satToMsat(LIMIT_SAT).toString()]);
    showBudget('at start');

    step(`Payee creates two hold invoices of ${formatMsat(satToMsat(PAYOUT_SAT))}: each fits the budget, both together do not`);
    const invoice1 = await createInvoice('merchant', ids.p1, satToMsat(PAYOUT_SAT), true);
    context.onAbort(() => cancelIfOpen('merchant', ids.p1));
    const invoice2 = await createInvoice('merchant', ids.p2, satToMsat(PAYOUT_SAT), true);
    context.onAbort(() => cancelIfOpen('merchant', ids.p2));

    step('Two worker processes decode their invoices, wait at a barrier, then reserve at the same instant');
    const workers = [
      new ServiceProcess(payArgs('customer-payer', ids.p1, 'payout', invoice1.paymentRequest, ALLOWANCE_MSAT, ['--budget', budgetId, '--wait-for-go']),
        { stdin: true, echo: event => { const text = describeEvent(event); return text === undefined ? undefined : `[worker 1] ${text}`; } }),
      new ServiceProcess(payArgs('customer-payer', ids.p2, 'payout', invoice2.paymentRequest, ALLOWANCE_MSAT, ['--budget', budgetId, '--wait-for-go']),
        { stdin: true, echo: event => { const text = describeEvent(event); return text === undefined ? undefined : `[worker 2] ${text}`; } }),
    ];
    await Promise.all(workers.map(worker => worker.waitForEvent('the worker to reach the barrier', event => event.event === 'ready', 60_000)));
    for (const worker of workers) worker.send('go');
    await Promise.all(workers.map(worker => worker.waitForEvent('admission or refusal', event => admitted(event) || refused(event), 60_000)));
    const winnerIndex = workers.findIndex(worker => worker.events.some(admitted));
    const loserIndex = workers.findIndex(worker => worker.events.some(refused));
    const outcomeCheck = verdict.check('exactly one of the two concurrent payouts was admitted', winnerIndex !== -1 && loserIndex !== -1
      && winnerIndex !== loserIndex, `admitted: worker ${winnerIndex + 1}, refused: worker ${loserIndex + 1}`);
    if (!outcomeCheck) throw new Error('the race did not produce one admission and one refusal');
    const winner = workers[winnerIndex] as ServiceProcess;
    const winnerInvoice = winnerIndex === 0 ? invoice1 : invoice2;
    const loserInvoice = loserIndex === 0 ? invoice1 : invoice2;
    const winnerOrder = winnerIndex === 0 ? ids.p1 : ids.p2;
    const loserOrder = loserIndex === 0 ? ids.p1 : ids.p2;
    const refusal = workers[loserIndex]?.events.find(refused);
    verdict.check('refusal follows from the reservation arithmetic', refusal !== undefined
      && BigInt(String(refusal.requestedMsat)) > BigInt(String(refusal.availableMsat)),
      `requested ${formatMsat(BigInt(String(refusal?.requestedMsat ?? '0')))}, available ${formatMsat(BigInt(String(refusal?.availableMsat ?? '0')))}`);
    await workers[loserIndex]?.finished(30_000, 'the refused worker');

    step('Kill the admitted worker while its HTLC is held: its payment is unresolved');
    await waitUntil('the payee node to hold the HTLC', async () =>
      (await context.read.merchant.lookupInvoice(winnerInvoice.paymentHash)).state === 'ACCEPTED' ? true : undefined, { timeoutMs: 60_000 });
    await winner.kill();
    const held = showBudget('while unresolved');
    verdict.check('the reservation stays held while the payment is unresolved',
      held.heldMsat === satToMsat(PAYOUT_SAT) + ALLOWANCE_MSAT && held.consumedMsat === 0n,
      `held ${formatMsat(held.heldMsat)}, consumed ${formatMsat(held.consumedMsat)}`);

    step(`A small payout (${formatMsat(satToMsat(SMALL_SAT))}) fits; the payee cancels it, so LND reports it failed`);
    const smallInvoice = await createInvoice('merchant', ids.small, satToMsat(SMALL_SAT), true);
    context.onAbort(() => cancelIfOpen('merchant', ids.small));
    const small = new ServiceProcess(payArgs('customer-payer', ids.small, 'payout', smallInvoice.paymentRequest, ALLOWANCE_MSAT, ['--budget', budgetId]),
      { echo: describeEvent });
    await small.waitForEvent('the small payout in flight', admitted, 60_000);
    await waitUntil('the payee node to hold the small payout', async () =>
      (await context.read.merchant.lookupInvoice(smallInvoice.paymentHash)).state === 'ACCEPTED' ? true : undefined, { timeoutMs: 60_000 });
    showBudget('with the small payout in flight');
    await runService(['receiver', 'cancel', '--as', 'merchant', '--order', ids.small], { echo: describeEvent });
    const smallExit = await small.finished(120_000, 'the small payout');
    const released = showBudget('after the failure');
    verdict.check('a failed payment releases its reservation', smallExit === 1 && released.availableMsat === held.availableMsat,
      `small payout exit ${smallExit} (1 = failed per LND), available back to ${formatMsat(released.availableMsat)}`);

    const nearMsat = satToMsat(NEAR_LIMIT_SAT);
    step(`A payout of ${formatMsat(nearMsat)} + ${formatMsat(ALLOWANCE_MSAT)} allowance while the first is still unresolved`);
    const nearInvoice = await createInvoice('merchant', ids.near, nearMsat, false);
    const nearArgs = payArgs('customer-payer', ids.near, 'payout', nearInvoice.paymentRequest, ALLOWANCE_MSAT, ['--budget', budgetId]);
    const nearFirst = await runService(nearArgs, { echo: describeEvent });
    verdict.check('refused while the held reservation counts in full', nearFirst.code === 3
      && nearMsat + ALLOWANCE_MSAT > released.availableMsat,
      `exit ${nearFirst.code}; needs ${formatMsat(nearMsat + ALLOWANCE_MSAT)}, available ${formatMsat(released.availableMsat)}`);

    step('Restart: reconcile the first payout with TrackPaymentV2 while the payee settles it');
    const reconciler = new ServiceProcess(['payer', 'reconcile', '--as', 'customer-payer', '--payment-hash', winnerInvoice.paymentHash,
      '--timeout-s', '300'], { echo: describeEvent });
    await reconciler.waitForEvent('TrackPaymentV2 to report the payout in flight',
      event => event.event === 'payment-update' && event.source === 'TrackPaymentV2', 60_000);
    await runService(['receiver', 'settle', '--as', 'merchant', '--order', winnerOrder], { echo: describeEvent });
    const reconciled = await reconciler.finished(120_000, 'the reconciler');
    const settledBudget = showBudget('after settlement');
    const winnerRecord = withPayer(context, 'customer-payer', store => store.payment(winnerInvoice.paymentHash));
    const actualFee = winnerRecord?.feeMsat ?? 0n;
    verdict.check('on success the reservation becomes principal + actual fee',
      reconciled === 0 && settledBudget.heldMsat === 0n && settledBudget.consumedMsat === satToMsat(PAYOUT_SAT) + actualFee,
      `consumed ${formatMsat(settledBudget.consumedMsat)} = ${formatMsat(satToMsat(PAYOUT_SAT))} + fee ${formatMsat(actualFee)}; `
      + `${formatMsat(ALLOWANCE_MSAT - actualFee)} of the allowance released`);

    step('The same payout request again, now that the reservation reflects the actual fee');
    const fits = nearMsat + ALLOWANCE_MSAT <= settledBudget.availableMsat;
    say(`needs ${formatMsat(nearMsat + ALLOWANCE_MSAT)}, available ${formatMsat(settledBudget.availableMsat)}: ${fits ? 'fits' : 'does not fit'}`);
    const nearSecond = await runService(nearArgs, { echo: describeEvent });
    verdict.check('admission follows the budget arithmetic', fits ? nearSecond.code === 0 : nearSecond.code === 3,
      `exit ${nearSecond.code}, expected ${fits ? '0 (paid)' : '3 (refused)'}`);

    step('Release the refused payout\'s invoice');
    await cancelIfOpen('merchant', loserOrder);

    step('Verdict from LND and the durable records');
    const evidence = await Promise.all([winnerInvoice, loserInvoice, smallInvoice, nearInvoice]
      .map(item => lndPayments(context, 'customer', item.paymentHash)));
    const [winnerLnd, loserLnd, smallLnd, nearLnd] = evidence;
    verdict.check('LND: the admitted payout paid once, the refused one never sent',
      winnerLnd?.payments.length === 1 && winnerLnd.payments[0]?.status === 'SUCCEEDED' && loserLnd?.payments.length === 0,
      `admitted: ${winnerLnd?.payments.map(item => item.status).join(', ') || 'none'}; refused: ${loserLnd?.payments.length ?? '?'} payment(s)`);
    verdict.check('LND: the canceled payout failed; the near-limit payout matches its admission',
      smallLnd?.payments[0]?.status === 'FAILED' && (fits ? nearLnd?.payments[0]?.status === 'SUCCEEDED' : nearLnd?.payments.length === 0),
      `small: ${smallLnd?.payments[0]?.status ?? 'none'}; near-limit: ${nearLnd?.payments.map(item => item.status).join(', ') || 'none'}`);
    const final = showBudget('at the end');
    const spent = evidence.flatMap(item => item.payments).filter(item => item.status === 'SUCCEEDED')
      .reduce((sum, item) => sum + item.valueMsat + item.feeMsat, 0n);
    verdict.check('budget consumed equals what LND actually paid, within the limit',
      final.heldMsat === 0n && final.consumedMsat === spent && final.consumedMsat <= final.limitMsat,
      `consumed ${formatMsat(final.consumedMsat)}, LND paid ${formatMsat(spent)} including fees, limit ${formatMsat(final.limitMsat)}`);
    fact('budget refusals recorded', withPayer(context, 'customer-payer', store => store.refusals(budgetId).length));

    step('What this budget does not do');
    say('The budget is enforced by this service, in its own database. It limits what this service sends. It does not limit');
    say('anyone who holds the pay-only macaroon itself: a copy of that file can call SendPaymentV2 directly, and LND will pay');
    say('within the node\'s balances. Enforcement against a leaked credential has to live where the credential is checked:');
    say('in the wallet or account backend, for example Lightning Terminal accounts, which bind a macaroon to a spending');
    say('balance that LND enforces. macwarden keeps such credentials short-lived, scoped and revocable; it does not cap amounts.');
    return verdict;
  });
