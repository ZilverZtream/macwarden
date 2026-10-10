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

  get notFound(): boolean {
    return this.grpcCode === NOT_FOUND || this.httpStatus === 404;
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

export function describeError(error: unknown): string {
  if (error instanceof LndError) return `LND error${error.grpcCode === undefined ? '' : ` (gRPC code ${error.grpcCode})`}: ${error.message}`;
  if (error instanceof TransportError) return `transport error during ${error.phase}: ${error.message}`;
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return String(error);
}
