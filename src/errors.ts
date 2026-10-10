export type InputStage = 'input-read' | 'input-form';
export type DecodeStage = 'v2-header' | 'packet' | 'identifier-version' |
  'identifier-proto' | 'identifier-limits' | 'identifier-root-key-id' | NwcStage | L402Stage | 'rune-syntax';
export type L402Stage = 'l402-form' | 'l402-preimage';
export type NwcStage = 'nwc-uri' | 'nwc-wallet-pubkey' | 'nwc-relay' | 'nwc-secret' | 'nwc-lud16';

export class UsageError extends Error {
  readonly code = 2;
  readonly stage = null;
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export class InputError extends Error {
  readonly code = 3;
  constructor(readonly stage: InputStage, message = `invalid credential ${stage}`) {
    super(message);
    this.name = 'InputError';
  }
}

export class DecodeError extends Error {
  readonly code = 3;
  constructor(readonly stage: DecodeStage, message = `invalid macaroon ${stage}`) {
    super(message);
    this.name = 'DecodeError';
  }
}

export class LndError extends Error {
  constructor(readonly code: 4 | 5, readonly stage: string, message: string) {
    super(message);
    this.name = 'LndError';
  }
}

/**
 * The request reached LND (the TLS connection was established) but no complete
 * response arrived: a timeout, reset, cancellation or oversized response. LND may
 * still carry out a mutating request, so its outcome is unknown, never "unchanged".
 */
export class LndUncertainError extends LndError {
  constructor(code: 4 | 5, stage: string, message: string) {
    super(code, stage, message);
    this.name = 'LndUncertainError';
  }
}
