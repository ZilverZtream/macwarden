/**
 * Three ways an RPC can end without a result. The distinction decides what the
 * caller may conclude:
 *
 * - LndError: LND answered. The answer is definite (for example "not found").
 * - TransportError in phase `connect`: no connection was established, so the
 *   request never reached LND.
 * - TransportError in any later phase, and ProtocolError: the request may have
 *   reached LND and the outcome is unknown. For a payment this is never a
 *   failure; the record stays unresolved until LND reports a terminal state.
 */

const NOT_FOUND = 5;

export class LndError extends Error {
  readonly grpcCode: number | undefined;
  readonly httpStatus: number | undefined;

  constructor(message: string, grpcCode: number | undefined, httpStatus: number | undefined) {
    super(message);
    this.name = 'LndError';
    this.grpcCode = grpcCode;
    this.httpStatus = httpStatus;
  }

  /**
   * LND itself answered NotFound: gRPC code 5, whatever the HTTP status. LND's REST gateway
   * (grpc-gateway) always sends the gRPC code with its error body (`{"code":5,"message":...}`).
   * A 404 without a code, bodiless or with a body such as `{"message":"Not Found"}` (an API
   * gateway) or `{"message":"no Route matched with those values"}` (Kong), comes from a proxy
   * or a wrong path in front of LND and proves nothing about the payment or invoice, so it is
   * not NotFound (the caller treats it as unknown), and definiteRefusal treats it as ambiguous.
   */
  get notFound(): boolean {
    return this.grpcCode === NOT_FOUND;
  }
}

export type TransportPhase = 'connect' | 'request' | 'response';

export class TransportError extends Error {
  readonly phase: TransportPhase;

  constructor(message: string, phase: TransportPhase, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'TransportError';
    this.phase = phase;
  }

  /** True when the request bytes can not have reached LND. */
  get notDelivered(): boolean {
    return this.phase === 'connect';
  }
}

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/**
 * gRPC status codes with which LND itself refuses a call: the request was handled
 * and nothing was created or sent. 2 Unknown is how LND returns most of its own
 * application errors (HTTP 500 from its gateway, for example "invoice with payment
 * hash already exists").
 */
const DEFINITE_REFUSAL_CODES: ReadonlySet<number> = new Set([
  2, // Unknown: an LND application error
  3, // InvalidArgument
  5, // NotFound
  6, // AlreadyExists
  7, // PermissionDenied
  8, // ResourceExhausted (request too large, rate limit inside LND)
  9, // FailedPrecondition
  11, // OutOfRange
  12, // Unimplemented
  16, // Unauthenticated
]);

/** HTTP statuses that a gateway or proxy in front of LND produces when the call was cut off, whatever the body says. */
const AMBIGUOUS_HTTP: ReadonlySet<number> = new Set([408, 499, 502, 503, 504]);

/**
 * Whether an error from a call that creates something in LND (AddInvoice,
 * AddHoldInvoice, SendPaymentV2) is a definite refusal, which lets a NotFound
 * lookup decide at once that nothing was created. The classes:
 *
 * - not delivered: a TransportError in phase `connect`; the request never left
 *   (handled before this is asked, without a lookup).
 * - definite refusal: an LndError with one of DEFINITE_REFUSAL_CODES from LND's
 *   gateway, or a 400-class response (other than 404, 408 and 499) whose body carries a
 *   message, and in neither case an HTTP status from AMBIGUOUS_HTTP. A 404 without a
 *   gRPC code is a proxy's or a wrong path's answer, not LND's (see notFound).
 * - ambiguous, everything else: gRPC 1 Cancelled, 4 DeadlineExceeded, 10 Aborted,
 *   13 Internal, 14 Unavailable, 15 DataLoss (the call may have been cut off after
 *   LND began handling it); HTTP 408, 499, 502, 503 or 504 from a gateway or proxy;
 *   a 404 without a gRPC code; a 5xx without an LND body; a TransportError after the connection was
 *   established; a ProtocolError (an unreadable answer); any other error. A lookup
 *   that finds nothing then is only a point-in-time absence: the receiver keeps the
 *   invoice `creating` until its creation window has passed, the payer keeps the
 *   payment `uncertain` for reconciliation.
 */
export function definiteRefusal(error: unknown): boolean {
  if (!(error instanceof LndError)) return false;
  const status = error.httpStatus;
  if (status !== undefined && AMBIGUOUS_HTTP.has(status)) return false;
  if (error.grpcCode !== undefined) return DEFINITE_REFUSAL_CODES.has(error.grpcCode);
  // No gRPC code: only a 400-class answer with a message from the body (not the client's "HTTP <status>" stand-in),
  // and never a 404: LND's own NotFound carries code 5, so a 404 without one is a proxy's or a wrong path's.
  return status !== undefined && status >= 400 && status < 500 && status !== 404 && error.message !== `HTTP ${status}`;
}

export function describeError(error: unknown): string {
  if (error instanceof LndError) return `LND error${error.grpcCode === undefined ? '' : ` (gRPC code ${error.grpcCode})`}: ${error.message}`;
  if (error instanceof TransportError) return `transport error during ${error.phase}: ${error.message}`;
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return String(error);
}
