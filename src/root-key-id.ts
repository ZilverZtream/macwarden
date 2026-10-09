// Root key IDs are uint64 and always canonical decimal strings in JSON (SPEC, Output).

export const MAX_ROOT_KEY_ID = 18446744073709551615n;

/**
 * True for a canonical decimal uint64: digits only, no leading zero except "0" itself, at most
 * 18446744073709551615. The one rule for every root key ID macwarden reads (registry, usage
 * and canary records, command selectors), so no reader accepts an ID another one refuses.
 */
export function isRootKeyId(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= MAX_ROOT_KEY_ID;
}
