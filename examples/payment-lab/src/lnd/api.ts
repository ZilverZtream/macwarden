import { assertHash, hexToBase64, hexToUrlParam } from '../util/encoding.ts';
import { asObject, array, integer, string } from './json.ts';
import type { LndRestClient, StreamDecision } from './rest.ts';
import {
  parseChannel, parseForwardingEvent, parseGetInfo, parseInvoice, parsePayment, parsePayReq, parsePendingOpenChannels,
  parseRoutes, parseWalletBalance,
  type Channel, type DecodedPayReq, type ForwardingEvent, type GetInfo, type Invoice, type Payment, type PendingOpenChannel,
  type Route, type WalletBalance,
} from './types.ts';

/**
 * One class per credential role. Each exposes only the RPCs its macaroon
 * permits, so the code shows the least-privilege split the lab bakes:
 *
 * - PayerApi    pay-only preset: SendPaymentV2, TrackPaymentV2, DecodePayReq, GetInfo
 * - InvoiceApi  invoice-only preset: invoices:read, invoices:write, GetInfo
 * - ReadApi     read-only preset: info, onchain, offchain, invoices and peers read access
 */

export class PayerApi {
  readonly #client: LndRestClient;
  constructor(client: LndRestClient) { this.#client = client; }

  async getInfo(): Promise<GetInfo> {
    return parseGetInfo(await this.#client.call('GET', '/v1/getinfo'));
  }

  async decodePayReq(paymentRequest: string): Promise<DecodedPayReq> {
    if (!/^ln[a-z0-9]+$/i.test(paymentRequest) || paymentRequest.length > 8192) throw new Error('not a BOLT 11 payment request');
    return parsePayReq(await this.#client.call('GET', `/v1/payreq/${encodeURIComponent(paymentRequest)}`));
  }

  /** routerrpc.SendPaymentV2. Every update is handed to `onUpdate` in order. */
  sendPaymentV2(request: { paymentRequest: string; feeLimitMsat: bigint; timeoutSeconds: number; maxParts: number },
    onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    const body = {
      payment_request: request.paymentRequest,
      fee_limit_msat: request.feeLimitMsat.toString(),
      timeout_seconds: request.timeoutSeconds,
      max_parts: request.maxParts,
      no_inflight_updates: false,
    };
    return this.#client.stream('POST', '/v2/router/send', body, message => onUpdate(parsePayment(message)), { signal });
  }

  /** routerrpc.TrackPaymentV2: the current state first, then every change until a terminal state. */
  trackPaymentV2(paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    const path = `/v2/router/track/${hexToUrlParam(assertHash(paymentHash))}?no_inflight_updates=false`;
    return this.#client.stream('GET', path, undefined, message => onUpdate(parsePayment(message)), { signal });
  }
}

export class InvoiceApi {
  readonly #client: LndRestClient;
  constructor(client: LndRestClient) { this.#client = client; }

  async getInfo(): Promise<GetInfo> {
    return parseGetInfo(await this.#client.call('GET', '/v1/getinfo'));
  }

  /** lnrpc.AddInvoice with a preimage chosen by the caller, so the payment hash is known before the call. */
  async addInvoice(request: { preimage: string; valueMsat: bigint; memo: string; expirySeconds: number }): Promise<{ paymentHash: string; paymentRequest: string; addIndex: bigint }> {
    const response = await this.#client.call('POST', '/v1/invoices', {
      r_preimage: hexToBase64(assertHash(request.preimage, 'preimage')),
      value_msat: request.valueMsat.toString(),
      memo: request.memo,
      expiry: String(request.expirySeconds),
    });
    return { paymentHash: Buffer.from(string(response, 'r_hash'), 'base64').toString('hex'),
      paymentRequest: string(response, 'payment_request'), addIndex: integer(response, 'add_index') };
  }

  /** invoicesrpc.AddHoldInvoice: LND accepts HTLCs for `hash` and holds them until SettleInvoice or CancelInvoice. */
  async addHoldInvoice(request: { paymentHash: string; valueMsat: bigint; memo: string; expirySeconds: number }): Promise<{ paymentRequest: string; addIndex: bigint }> {
    const response = await this.#client.call('POST', '/v2/invoices/hodl', {
      hash: hexToBase64(assertHash(request.paymentHash)),
      value_msat: request.valueMsat.toString(),
      memo: request.memo,
      expiry: String(request.expirySeconds),
    });
    return { paymentRequest: string(response, 'payment_request'), addIndex: integer(response, 'add_index') };
  }

  async settleInvoice(preimage: string): Promise<void> {
    await this.#client.call('POST', '/v2/invoices/settle', { preimage: hexToBase64(assertHash(preimage, 'preimage')) });
  }

  async cancelInvoice(paymentHash: string): Promise<void> {
    await this.#client.call('POST', '/v2/invoices/cancel', { payment_hash: hexToBase64(assertHash(paymentHash)) });
  }

  async lookupInvoice(paymentHash: string, signal?: AbortSignal): Promise<Invoice> {
    return parseInvoice(await this.#client.call('GET', `/v2/invoices/lookup?payment_hash=${hexToUrlParam(assertHash(paymentHash))}`,
      undefined, { signal }));
  }

  /**
   * lnrpc.SubscribeInvoices. With a non-zero settle index LND first replays every
   * invoice settled after it, then streams live updates. Index 0 means no replay.
   */
  subscribeInvoices(from: { addIndex: bigint; settleIndex: bigint }, onInvoice: (invoice: Invoice) => StreamDecision,
    signal?: AbortSignal): Promise<void> {
    const path = `/v1/invoices/subscribe?add_index=${from.addIndex}&settle_index=${from.settleIndex}`;
    return this.#client.stream('GET', path, undefined, message => onInvoice(parseInvoice(message)), { signal });
  }

  /** invoicesrpc.SubscribeSingleInvoice: every state change of one invoice, including ACCEPTED for a hold invoice. */
  subscribeSingleInvoice(paymentHash: string, onInvoice: (invoice: Invoice) => StreamDecision, signal?: AbortSignal): Promise<void> {
    return this.#client.stream('GET', `/v2/invoices/subscribe/${hexToUrlParam(assertHash(paymentHash))}`, undefined,
      message => onInvoice(parseInvoice(message)), { signal });
  }
}

export interface PaymentsPage {
  payments: Payment[];
  lastIndexOffset: bigint;
}

export class ReadApi {
  readonly #client: LndRestClient;
  constructor(client: LndRestClient) { this.#client = client; }

  async getInfo(): Promise<GetInfo> {
    return parseGetInfo(await this.#client.call('GET', '/v1/getinfo'));
  }

  async listPaymentsPage(indexOffset: bigint, maxPayments: number): Promise<PaymentsPage> {
    const response = await this.#client.call('GET',
      `/v1/payments?include_incomplete=true&index_offset=${indexOffset}&max_payments=${maxPayments}&reversed=false`);
    return { payments: array(response, 'payments').map(parsePayment), lastIndexOffset: integer(response, 'last_index_offset') };
  }

  // Lightning.LookupInvoice (GET /v1/invoice/{hex hash}) needs only invoices:read; the v2
  // invoicesrpc lookup needs invoices:write in LND v0.21.4, which a read-only credential lacks.
  async lookupInvoice(paymentHash: string): Promise<Invoice> {
    return parseInvoice(await this.#client.call('GET', `/v1/invoice/${assertHash(paymentHash)}`));
  }

  async listChannels(): Promise<Channel[]> {
    return array(await this.#client.call('GET', '/v1/channels'), 'channels').map(parseChannel);
  }

  async pendingOpenChannels(): Promise<PendingOpenChannel[]> {
    return parsePendingOpenChannels(await this.#client.call('GET', '/v1/channels/pending'));
  }

  async walletBalance(): Promise<WalletBalance> {
    return parseWalletBalance(await this.#client.call('GET', '/v1/balance/blockchain'));
  }

  /** lnrpc.QueryRoutes from this node. LND answers an error when it finds no path. */
  async queryRoutes(destination: string, amountMsat: bigint): Promise<Route[]> {
    if (!/^[0-9a-f]{66}$/.test(destination)) throw new Error('destination must be a 33-byte hex public key');
    return parseRoutes(await this.#client.call('GET', `/v1/graph/routes/${destination}/0?amt_msat=${amountMsat}`));
  }

  async forwardingHistory(startTimeSeconds: bigint, endTimeSeconds: bigint, indexOffset: number, maxEvents: number): Promise<{ events: ForwardingEvent[]; lastOffsetIndex: number }> {
    const response = await this.#client.call('POST', '/v1/switch', {
      start_time: startTimeSeconds.toString(),
      end_time: endTimeSeconds.toString(),
      index_offset: indexOffset,
      num_max_events: maxEvents,
    });
    return { events: array(response, 'forwarding_events').map(parseForwardingEvent),
      lastOffsetIndex: Number(integer(asObject(response, 'ForwardingHistoryResponse'), 'last_offset_index')) };
  }
}
