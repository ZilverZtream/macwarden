/** Amounts are carried as millisatoshi bigints end to end: LND's REST API sends uint64 values as strings. */

export const MSAT_PER_SAT = 1000n;

export function satToMsat(sat: bigint): bigint {
  return sat * MSAT_PER_SAT;
}

/** `25000000n` → `25,000 sat`; `1121n` → `1.121 sat`. */
export function formatMsat(msat: bigint): string {
  const negative = msat < 0n;
  const absolute = negative ? -msat : msat;
  const sat = absolute / MSAT_PER_SAT;
  const rest = absolute % MSAT_PER_SAT;
  const whole = sat.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = rest === 0n ? '' : `.${rest.toString().padStart(3, '0').replace(/0+$/, '')}`;
  return `${negative ? '-' : ''}${whole}${fraction} sat`;
}

/** Parses a non-negative integer given on the command line. */
export function parseAmount(text: string, what: string): bigint {
  if (!/^(0|[1-9][0-9]{0,18})$/.test(text)) throw new Error(`${what} must be a non-negative integer`);
  return BigInt(text);
}
