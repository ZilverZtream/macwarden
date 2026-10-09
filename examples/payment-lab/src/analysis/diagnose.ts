import type { ReadApi } from '../lnd/api.ts';
import { describeError } from '../lnd/errors.ts';
import type { Channel, Payment } from '../lnd/types.ts';
import { formatMsat, satToMsat } from '../util/money.ts';

/**
 * A liquidity diagnosis for a payment this node sends, built only from what
 * the sending node can see with a read-only credential: its wallet, its own
 * channels (balances, reserves, commitment fees, pending HTLCs), a route query
 * and the payment's HTLC attempts. Other nodes' balances are not visible, and
 * the findings say so.
 */

export interface ChannelView {
  chanId: string;
  remotePubkey: string;
  active: boolean;
  initiator: boolean;
  capacitySat: bigint;
  localSat: bigint;
  remoteSat: bigint;
  localReserveSat: bigint;
  remoteReserveSat: bigint;
  commitFeeSat: bigint;
  /** Local balance above our reserve. An upper bound: LND also keeps a fee buffer for new HTLCs on channels it opened. */
  sendableSat: bigint;
  /** Remote balance above the peer's reserve: what the peer could still push to us. */
  receivableSat: bigint;
  pendingOutgoingSat: bigint;
  pendingIncomingSat: bigint;
  pendingHtlcCount: number;
}

export interface AttemptView {
  attemptId: string;
  status: string;
  route: string;
  principalMsat: bigint;
  feeMsat: bigint;
  failureCode: string | undefined;
  failureSourceIndex: number | undefined;
  failingNode: string | undefined;
}

export interface Diagnosis {
  amountMsat: bigint;
  destination: string;
  onChain: { confirmedSat: bigint; unconfirmedSat: bigint; lockedSat: bigint; reservedForAnchorsSat: bigint };
  channels: ChannelView[];
  pendingOpen: { remotePubkey: string; capacitySat: bigint; localSat: bigint }[];
  totals: { capacitySat: bigint; localSat: bigint; remoteSat: bigint; sendableSat: bigint; receivableSat: bigint; inactive: number };
  routeQuery: { found: boolean; detail: string };
  payment: { status: string; failureReason: string; attempts: AttemptView[] } | undefined;
  findings: string[];
}

const max0 = (value: bigint): bigint => (value > 0n ? value : 0n);

function channelView(channel: Channel): ChannelView {
  const outgoing = channel.pendingHtlcs.filter(item => !item.incoming);
  const incoming = channel.pendingHtlcs.filter(item => item.incoming);
  return {
    chanId: channel.chanId,
    remotePubkey: channel.remotePubkey,
    active: channel.active,
    initiator: channel.initiator,
    capacitySat: channel.capacitySat,
    localSat: channel.localBalanceSat,
    remoteSat: channel.remoteBalanceSat,
    localReserveSat: channel.localReserveSat,
    remoteReserveSat: channel.remoteReserveSat,
    commitFeeSat: channel.commitFeeSat,
    sendableSat: max0(channel.localBalanceSat - channel.localReserveSat),
    receivableSat: max0(channel.remoteBalanceSat - channel.remoteReserveSat),
    pendingOutgoingSat: outgoing.reduce((sum, item) => sum + item.amountSat, 0n),
    pendingIncomingSat: incoming.reduce((sum, item) => sum + item.amountSat, 0n),
    pendingHtlcCount: channel.pendingHtlcs.length,
  };
}

const FAILURE_MEANING: Record<string, string> = {
  TEMPORARY_CHANNEL_FAILURE: 'the outgoing channel at that node could not carry the HTLC (usually too little balance on its side, or the channel is busy)',
  UNKNOWN_NEXT_PEER: 'that node does not know or cannot reach the next channel in the route',
  FEE_INSUFFICIENT: 'the fee offered was below that node\'s policy (often a policy update the sender had not yet received)',
  INCORRECT_CLTV_EXPIRY: 'the time lock did not match that node\'s policy',
  EXPIRY_TOO_SOON: 'the time lock was too close for that node',
  CHANNEL_DISABLED: 'that node has disabled the outgoing channel',
  AMOUNT_BELOW_MINIMUM: 'the amount is below the outgoing channel\'s minimum HTLC',
  INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS: 'the final node rejected the payment (unknown or canceled invoice, wrong amount, or expired)',
  MPP_TIMEOUT: 'the final node did not receive the full amount of a multi-part payment in time',
  PERMANENT_CHANNEL_FAILURE: 'the outgoing channel at that node is unusable',
  TEMPORARY_NODE_FAILURE: 'that node reported a temporary problem',
  PERMANENT_NODE_FAILURE: 'that node reported a permanent problem',
};

export async function diagnose(read: ReadApi, input: { amountMsat: bigint; destination: string; payment?: Payment }): Promise<Diagnosis> {
  const [info, wallet, channels, pendingOpen] = await Promise.all([read.getInfo(), read.walletBalance(), read.listChannels(), read.pendingOpenChannels()]);
  const views = channels.map(channelView);
  const active = views.filter(item => item.active);
  const totals = {
    capacitySat: views.reduce((sum, item) => sum + item.capacitySat, 0n),
    localSat: views.reduce((sum, item) => sum + item.localSat, 0n),
    remoteSat: views.reduce((sum, item) => sum + item.remoteSat, 0n),
    sendableSat: active.reduce((sum, item) => sum + item.sendableSat, 0n),
    receivableSat: active.reduce((sum, item) => sum + item.receivableSat, 0n),
    inactive: views.length - active.length,
  };
  let routeQuery: Diagnosis['routeQuery'];
  try {
    const routes = await read.queryRoutes(input.destination, input.amountMsat);
    const route = routes[0];
    routeQuery = route === undefined
      ? { found: false, detail: 'QueryRoutes returned no route' }
      : { found: true, detail: `QueryRoutes found a ${route.hops.length}-hop route with ${formatMsat(route.totalFeesMsat)} in fees` };
  } catch (error) {
    routeQuery = { found: false, detail: `QueryRoutes: ${describeError(error)}` };
  }
  const attempts: AttemptView[] = (input.payment?.htlcs ?? []).map(attempt => ({
    attemptId: attempt.attemptId,
    status: attempt.status,
    route: attempt.route.hops.map(hop => hop.chanId).join(' > '),
    principalMsat: attempt.principalMsat,
    feeMsat: attempt.route.totalFeesMsat,
    failureCode: attempt.failureCode,
    failureSourceIndex: attempt.failureSourceIndex,
    failingNode: attempt.failureSourceIndex === undefined ? undefined
      : attempt.failureSourceIndex === 0 ? info.identityPubkey : attempt.route.hops[attempt.failureSourceIndex - 1]?.pubKey,
  }));
  const diagnosis: Diagnosis = {
    amountMsat: input.amountMsat,
    destination: input.destination,
    onChain: wallet,
    channels: views,
    pendingOpen: pendingOpen.map(item => ({ remotePubkey: item.remotePubkey, capacitySat: item.capacitySat, localSat: item.localBalanceSat })),
    totals,
    routeQuery,
    payment: input.payment === undefined ? undefined
      : { status: input.payment.status, failureReason: input.payment.failureReason, attempts },
    findings: [],
  };
  diagnosis.findings = findings(diagnosis, info.identityPubkey);
  return diagnosis;
}

function findings(d: Diagnosis, self: string): string[] {
  const out: string[] = [];
  const amount = formatMsat(d.amountMsat);
  const sendable = formatMsat(satToMsat(d.totals.sendableSat));
  const onChain = formatMsat(satToMsat(d.onChain.confirmedSat));
  const capacity = formatMsat(satToMsat(d.totals.capacitySat));
  const amountSat = (d.amountMsat + 999n) / 1000n;

  // On-chain versus channel liquidity.
  if (d.onChain.confirmedSat >= amountSat && d.totals.sendableSat < amountSat) {
    out.push(`On-chain funds are not Lightning liquidity. The wallet holds ${onChain} confirmed, enough for ${amount}, but a Lightning payment `
      + `can only spend channel balance, and the channels can send at most ${sendable}. On-chain funds become sendable only after they are `
      + 'moved into a channel (a new channel, or a splice).');
  } else {
    out.push(`The wallet holds ${onChain} confirmed on-chain; the channels can send at most ${sendable}.`);
  }

  // Capacity versus directional balance.
  out.push(`Capacity is not spendable balance. The ${d.channels.length} channel(s) have ${capacity} capacity in total, split into `
    + `${formatMsat(satToMsat(d.totals.localSat))} on this side (can be sent) and ${formatMsat(satToMsat(d.totals.remoteSat))} on the peers' `
    + 'side (can be received). A payment moves balance from the local side to the remote side of every channel it crosses.');
  for (const channel of d.channels) {
    out.push(`  channel ${channel.chanId}${channel.active ? '' : ' (inactive)'}: capacity ${formatMsat(satToMsat(channel.capacitySat))}, `
      + `local ${formatMsat(satToMsat(channel.localSat))} (reserve ${formatMsat(satToMsat(channel.localReserveSat))}, sendable up to `
      + `${formatMsat(satToMsat(channel.sendableSat))}), remote ${formatMsat(satToMsat(channel.remoteSat))} (peer reserve `
      + `${formatMsat(satToMsat(channel.remoteReserveSat))}), commitment fee ${formatMsat(satToMsat(channel.commitFeeSat))} paid by `
      + `${channel.initiator ? 'this node' : 'the peer'}, ${channel.pendingHtlcCount} pending HTLC(s)`);
  }

  // Reserves and pending HTLCs.
  const reserves = d.channels.reduce((sum, item) => sum + item.localReserveSat, 0n);
  out.push(`Reserves: each side must keep its channel reserve (${formatMsat(satToMsat(reserves))} on this side in total) and cannot send it; `
    + 'the side that opened a channel also pays its commitment fee from its balance, and LND keeps a further fee buffer for new HTLCs.');
  const pendingOut = d.channels.reduce((sum, item) => sum + item.pendingOutgoingSat, 0n);
  const pendingCount = d.channels.reduce((sum, item) => sum + item.pendingHtlcCount, 0);
  if (pendingCount > 0) {
    out.push(`${pendingCount} HTLC(s) are pending; ${formatMsat(satToMsat(pendingOut))} outgoing is locked until they resolve and is not sendable.`);
  }
  if (d.totals.inactive > 0) out.push(`${d.totals.inactive} channel(s) are inactive; their balance cannot be used until the peer reconnects.`);
  if (d.pendingOpen.length > 0) out.push(`${d.pendingOpen.length} channel(s) are still opening and cannot carry payments yet.`);

  // Send versus receive.
  out.push(`Sending and receiving need opposite sides. Sending ${amount} needs that much local balance here and on the outgoing side of `
    + `every hop to the destination; receiving needs remote (inbound) balance toward the receiver. This node could still receive up to `
    + `${formatMsat(satToMsat(d.totals.receivableSat))}, which does not help it send.`);

  out.push(`Route check: ${d.routeQuery.detail}.`);

  // What the payment itself says.
  if (d.payment !== undefined) {
    const reason = d.payment.failureReason;
    if (reason === 'FAILURE_REASON_INSUFFICIENT_BALANCE') {
      out.push('LND failed the payment with INSUFFICIENT_BALANCE: the local balance of this node\'s channels together was below the amount '
        + 'plus fees, so no HTLC was sent and nothing was learned about other nodes.');
    } else if (reason === 'FAILURE_REASON_NO_ROUTE' && d.payment.attempts.length === 0) {
      out.push('LND failed the payment with NO_ROUTE before sending any HTLC: from its view of the graph and its own balances no route '
        + 'could carry the amount.');
    } else if (reason !== 'FAILURE_REASON_NONE') {
      out.push(`LND failed the payment with ${reason} after ${d.payment.attempts.length} HTLC attempt(s).`);
    }
    for (const attempt of d.payment.attempts.filter(item => item.status === 'FAILED')) {
      const where = attempt.failureSourceIndex === undefined ? 'an unknown hop'
        : attempt.failingNode === self ? 'this node' : `hop ${attempt.failureSourceIndex} (${attempt.failingNode ?? 'unknown node'})`;
      const meaning = attempt.failureCode === undefined ? '' : `: ${FAILURE_MEANING[attempt.failureCode] ?? 'see the BOLT 4 failure code'}`;
      out.push(`  attempt ${attempt.attemptId} over ${attempt.route || 'no route'} for ${formatMsat(attempt.principalMsat)} failed at ${where} `
        + `with ${attempt.failureCode ?? 'no failure message'}${meaning}`);
    }
    const sources = new Set(d.payment.attempts.filter(item => item.status === 'FAILED').map(item => item.failingNode ?? '?'));
    if (sources.size > 1) {
      out.push(`Attempts failed at ${sources.size} different nodes: more than one constraint applied, so there is no single bottleneck to fix.`);
    }
  }
  out.push('Limits of this diagnosis: a failure names the first node that refused one attempt. The balances of other nodes\' channels are '
    + 'not visible from here, a later attempt may fail elsewhere, and balances change between attempts, so one failure does not '
    + 'always locate all the missing liquidity.');
  return out;
}
