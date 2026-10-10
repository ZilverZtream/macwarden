import { assertHash, base64ToHex, presentPreimage } from '../util/encoding.ts';
import { array, asObject, boolean, checkedNonNegative, enumName, identifier, integer, optionalObject, smallInteger, string, type JsonObject } from './json.ts';

/** Parsed LND messages. Field names follow lnrpc; amounts are millisatoshi bigints. */

const PAYMENT_STATUS = ['UNKNOWN', 'IN_FLIGHT', 'SUCCEEDED', 'FAILED', 'INITIATED'] as const;
const FAILURE_REASON = ['FAILURE_REASON_NONE', 'FAILURE_REASON_TIMEOUT', 'FAILURE_REASON_NO_ROUTE', 'FAILURE_REASON_ERROR',
  'FAILURE_REASON_INCORRECT_PAYMENT_DETAILS', 'FAILURE_REASON_INSUFFICIENT_BALANCE', 'FAILURE_REASON_CANCELED'] as const;
const HTLC_STATUS = ['IN_FLIGHT', 'SUCCEEDED', 'FAILED'] as const;
const INVOICE_STATE = ['OPEN', 'SETTLED', 'CANCELED', 'ACCEPTED'] as const;
const INVOICE_HTLC_STATE = ['ACCEPTED', 'SETTLED', 'CANCELED'] as const;
const FAILURE_CODE = ['RESERVED', 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS', 'INCORRECT_PAYMENT_AMOUNT', 'FINAL_INCORRECT_CLTV_EXPIRY',
  'FINAL_INCORRECT_HTLC_AMOUNT', 'FINAL_EXPIRY_TOO_SOON', 'INVALID_REALM', 'EXPIRY_TOO_SOON', 'INVALID_ONION_VERSION',
  'INVALID_ONION_HMAC', 'INVALID_ONION_KEY', 'AMOUNT_BELOW_MINIMUM', 'FEE_INSUFFICIENT', 'INCORRECT_CLTV_EXPIRY',
  'CHANNEL_DISABLED', 'TEMPORARY_CHANNEL_FAILURE', 'REQUIRED_NODE_FEATURE_MISSING', 'REQUIRED_CHANNEL_FEATURE_MISSING',
  'UNKNOWN_NEXT_PEER', 'TEMPORARY_NODE_FAILURE', 'PERMANENT_NODE_FAILURE', 'PERMANENT_CHANNEL_FAILURE', 'EXPIRY_TOO_FAR',
  'MPP_TIMEOUT', 'INVALID_ONION_PAYLOAD', 'INVALID_ONION_BLINDING'] as const;

export type PaymentStatus = typeof PAYMENT_STATUS[number];
export type InvoiceState = typeof INVOICE_STATE[number];

export interface GetInfo {
  identityPubkey: string;
  alias: string;
  blockHeight: number;
  syncedToChain: boolean;
  syncedToGraph: boolean;
  version: string;
  network: string;
}

export function parseGetInfo(value: unknown): GetInfo {
  const o = asObject(value, 'GetInfo');
  const chain = array(o, 'chains')[0];
  return {
    identityPubkey: string(o, 'identity_pubkey'),
    alias: string(o, 'alias'),
    blockHeight: smallInteger(o, 'block_height'),
    syncedToChain: boolean(o, 'synced_to_chain'),
    syncedToGraph: boolean(o, 'synced_to_graph'),
    version: string(o, 'version'),
    network: chain === undefined ? '' : string(asObject(chain, 'chain'), 'network'),
  };
}

export interface RouteHop {
  chanId: string;
  pubKey: string;
  amtToForwardMsat: bigint;
  feeMsat: bigint;
}

export interface Route {
  totalAmtMsat: bigint;
  totalFeesMsat: bigint;
  hops: RouteHop[];
}

function parseRoute(value: unknown): Route {
  const o = asObject(value, 'route');
  return {
    totalAmtMsat: integer(o, 'total_amt_msat'),
    totalFeesMsat: integer(o, 'total_fees_msat'),
    hops: array(o, 'hops').map(item => {
      const hop = asObject(item, 'hop');
      return { chanId: identifier(hop, 'chan_id'), pubKey: string(hop, 'pub_key'),
        amtToForwardMsat: integer(hop, 'amt_to_forward_msat'), feeMsat: integer(hop, 'fee_msat') };
    }),
  };
}

/** One HTLC attempt: an execution detail of a payment, never a payment of its own. */
export interface HtlcAttempt {
  attemptId: string;
  status: string;
  route: Route;
  /** Amount delivered to the destination by this attempt (route total minus route fees). */
  principalMsat: bigint;
  attemptTimeNs: bigint;
  resolveTimeNs: bigint;
  failureCode: string | undefined;
  /** Index into the route: 0 is the sending node, n the n-th hop. */
  failureSourceIndex: number | undefined;
}

function parseAttempt(value: unknown): HtlcAttempt {
  const o = asObject(value, 'htlc attempt');
  const route = parseRoute(o.route ?? {});
  const failure = optionalObject(o, 'failure');
  return {
    attemptId: identifier(o, 'attempt_id'),
    status: enumName(o, 'status', HTLC_STATUS),
    route,
    principalMsat: checkedNonNegative(route.totalAmtMsat - route.totalFeesMsat, 'htlc attempt principal'),
    attemptTimeNs: integer(o, 'attempt_time_ns'),
    resolveTimeNs: integer(o, 'resolve_time_ns'),
    failureCode: failure === undefined ? undefined : enumName(failure, 'code', FAILURE_CODE),
    failureSourceIndex: failure === undefined ? undefined : smallInteger(failure, 'failure_source_index'),
  };
}

/** A Lightning payment as LND tracks it, identified by its payment hash. */
export interface Payment {
  paymentHash: string;
  status: PaymentStatus | string;
  valueMsat: bigint;
  feeMsat: bigint;
  preimage: string | undefined;
  paymentRequest: string;
  failureReason: string;
  creationTimeNs: bigint;
  paymentIndex: string;
  htlcs: HtlcAttempt[];
}

export function parsePayment(value: unknown): Payment {
  const o = asObject(value, 'payment');
  return {
    paymentHash: assertHash(string(o, 'payment_hash')),
    status: enumName(o, 'status', PAYMENT_STATUS),
    valueMsat: integer(o, 'value_msat'),
    feeMsat: integer(o, 'fee_msat'),
    preimage: presentPreimage(string(o, 'payment_preimage')),
    paymentRequest: string(o, 'payment_request'),
    failureReason: enumName(o, 'failure_reason', FAILURE_REASON),
    creationTimeNs: integer(o, 'creation_time_ns'),
    paymentIndex: identifier(o, 'payment_index'),
    htlcs: array(o, 'htlcs').map(parseAttempt),
  };
}

export function isTerminal(status: string): boolean {
  return status === 'SUCCEEDED' || status === 'FAILED';
}

export interface InvoiceHtlc {
  chanId: string;
  htlcIndex: string;
  amtMsat: bigint;
  state: string;
}

/** An invoice on the receiving node, identified by its payment hash. */
export interface Invoice {
  paymentHash: string;
  state: InvoiceState | string;
  memo: string;
  valueMsat: bigint;
  amtPaidMsat: bigint;
  addIndex: bigint;
  settleIndex: bigint;
  paymentRequest: string;
  htlcs: InvoiceHtlc[];
}

export function parseInvoice(value: unknown): Invoice {
  const o = asObject(value, 'invoice');
  return {
    paymentHash: assertHash(base64ToHex(string(o, 'r_hash'))),
    state: enumName(o, 'state', INVOICE_STATE),
    memo: string(o, 'memo'),
    valueMsat: integer(o, 'value_msat'),
    amtPaidMsat: integer(o, 'amt_paid_msat'),
    addIndex: integer(o, 'add_index'),
    settleIndex: integer(o, 'settle_index'),
    paymentRequest: string(o, 'payment_request'),
    htlcs: array(o, 'htlcs').map(item => {
      const htlc = asObject(item, 'invoice htlc');
      return { chanId: identifier(htlc, 'chan_id'), htlcIndex: identifier(htlc, 'htlc_index'),
        amtMsat: integer(htlc, 'amt_msat'), state: enumName(htlc, 'state', INVOICE_HTLC_STATE) };
    }),
  };
}

export interface DecodedPayReq {
  destination: string;
  paymentHash: string;
  amountMsat: bigint;
  timestamp: bigint;
  expirySeconds: bigint;
  description: string;
}

export function parsePayReq(value: unknown): DecodedPayReq {
  const o = asObject(value, 'PayReq');
  return {
    destination: string(o, 'destination'),
    paymentHash: assertHash(string(o, 'payment_hash')),
    amountMsat: integer(o, 'num_msat'),
    timestamp: integer(o, 'timestamp'),
    expirySeconds: integer(o, 'expiry'),
    description: string(o, 'description'),
  };
}

export interface PendingHtlc {
  incoming: boolean;
  amountSat: bigint;
  hashLock: string;
  expirationHeight: number;
}

export interface Channel {
  chanId: string;
  channelPoint: string;
  remotePubkey: string;
  active: boolean;
  initiator: boolean;
  capacitySat: bigint;
  localBalanceSat: bigint;
  remoteBalanceSat: bigint;
  commitFeeSat: bigint;
  unsettledBalanceSat: bigint;
  localReserveSat: bigint;
  remoteReserveSat: bigint;
  pendingHtlcs: PendingHtlc[];
}

function reserve(o: JsonObject, constraintsKey: string, deprecatedKey: string): bigint {
  const constraints = optionalObject(o, constraintsKey);
  const value = constraints === undefined ? 0n : integer(constraints, 'chan_reserve_sat');
  return value === 0n ? integer(o, deprecatedKey) : value;
}

export function parseChannel(value: unknown): Channel {
  const o = asObject(value, 'channel');
  return {
    // LND v0.21 reports the 32-byte channel ID as chan_id and the short channel ID as scid;
    // earlier releases put the short channel ID in chan_id. Routes and forwards use the short one.
    chanId: 'scid' in o ? identifier(o, 'scid') : identifier(o, 'chan_id'),
    channelPoint: string(o, 'channel_point'),
    remotePubkey: string(o, 'remote_pubkey'),
    active: boolean(o, 'active'),
    initiator: boolean(o, 'initiator'),
    capacitySat: integer(o, 'capacity'),
    localBalanceSat: integer(o, 'local_balance'),
    remoteBalanceSat: integer(o, 'remote_balance'),
    commitFeeSat: integer(o, 'commit_fee'),
    unsettledBalanceSat: integer(o, 'unsettled_balance'),
    localReserveSat: reserve(o, 'local_constraints', 'local_chan_reserve_sat'),
    remoteReserveSat: reserve(o, 'remote_constraints', 'remote_chan_reserve_sat'),
    pendingHtlcs: array(o, 'pending_htlcs').map(item => {
      const htlc = asObject(item, 'pending htlc');
      return { incoming: boolean(htlc, 'incoming'), amountSat: integer(htlc, 'amount'),
        hashLock: base64ToHex(string(htlc, 'hash_lock')), expirationHeight: smallInteger(htlc, 'expiration_height') };
    }),
  };
}

export interface WalletBalance {
  confirmedSat: bigint;
  unconfirmedSat: bigint;
  lockedSat: bigint;
  reservedForAnchorsSat: bigint;
}

export function parseWalletBalance(value: unknown): WalletBalance {
  const o = asObject(value, 'WalletBalance');
  return { confirmedSat: integer(o, 'confirmed_balance'), unconfirmedSat: integer(o, 'unconfirmed_balance'),
    lockedSat: integer(o, 'locked_balance'), reservedForAnchorsSat: integer(o, 'reserved_balance_anchor_chan') };
}

export interface PendingOpenChannel {
  remotePubkey: string;
  channelPoint: string;
  capacitySat: bigint;
  localBalanceSat: bigint;
}

export function parsePendingOpenChannels(value: unknown): PendingOpenChannel[] {
  const o = asObject(value, 'PendingChannels');
  return array(o, 'pending_open_channels').map(item => {
    const channel = asObject(asObject(item, 'pending open channel').channel ?? {}, 'channel');
    return { remotePubkey: string(channel, 'remote_node_pub'), channelPoint: string(channel, 'channel_point'),
      capacitySat: integer(channel, 'capacity'), localBalanceSat: integer(channel, 'local_balance') };
  });
}

export interface ForwardingEvent {
  timestampNs: bigint;
  chanIdIn: string;
  chanIdOut: string;
  amtInMsat: bigint;
  amtOutMsat: bigint;
  feeMsat: bigint;
}

export function parseForwardingEvent(value: unknown): ForwardingEvent {
  const o = asObject(value, 'forwarding event');
  return { timestampNs: integer(o, 'timestamp_ns'), chanIdIn: identifier(o, 'chan_id_in'),
    chanIdOut: identifier(o, 'chan_id_out'), amtInMsat: integer(o, 'amt_in_msat'),
    amtOutMsat: integer(o, 'amt_out_msat'), feeMsat: integer(o, 'fee_msat') };
}

export function parseRoutes(value: unknown): Route[] {
  return array(asObject(value, 'QueryRoutesResponse'), 'routes').map(parseRoute);
}
