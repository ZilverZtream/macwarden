/**
 * Offline reading of a BOLT11 payment request: only what a replay needs to tell
 * whether two invoice strings are the same payment, without asking LND. The
 * bech32 checksum is verified, so a damaged string is never read as a hash.
 * Nothing here validates an invoice for paying; that is DecodePayReq's job.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const SIGNATURE_WORDS = 104; // 65 bytes of signature and recovery ID
const TIMESTAMP_WORDS = 7;
const CHECKSUM_WORDS = 6;
const MAX_LENGTH = 8192;
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

function polymod(values: readonly number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let bit = 0; bit < 5; bit += 1) if ((top >>> bit) & 1) checksum ^= GENERATOR[bit] ?? 0;
  }
  return checksum;
}

/** The 5-bit words after the separator, checksum verified and removed; undefined when the string is not valid bech32. */
function bech32Words(paymentRequest: string): { hrp: string; words: number[] } | undefined {
  if (paymentRequest.length > MAX_LENGTH) return undefined;
  // Printable ASCII before any case folding: toLowerCase maps look-alikes such as U+212A (Kelvin sign) to ASCII
  // letters, which would read a string LND refuses as a valid invoice.
  if (!PRINTABLE_ASCII.test(paymentRequest)) return undefined;
  const lower = paymentRequest.toLowerCase();
  if (lower !== paymentRequest && paymentRequest.toUpperCase() !== paymentRequest) return undefined; // mixed case is invalid
  const separator = lower.lastIndexOf('1');
  if (separator < 1 || lower.length - separator - 1 < CHECKSUM_WORDS) return undefined;
  const hrp = lower.slice(0, separator);
  if (!/^[\x21-\x7e]+$/.test(hrp)) return undefined;
  const words: number[] = [];
  for (const char of lower.slice(separator + 1)) {
    const word = CHARSET.indexOf(char);
    if (word < 0) return undefined;
    words.push(word);
  }
  const expanded = [...hrp].map(char => char.charCodeAt(0) >> 5).concat([0], [...hrp].map(char => char.charCodeAt(0) & 31));
  if (polymod([...expanded, ...words]) !== 1) return undefined;
  return { hrp, words: words.slice(0, -CHECKSUM_WORDS) };
}

/**
 * The payment hash (`p` field) of a BOLT11 payment request, as 64 lowercase hex
 * characters, or undefined when the string is not a well-formed one. BOLT11 is
 * case-insensitive, so an upper-case invoice (as QR codes carry it) gives the same hash.
 */
export function bolt11PaymentHash(paymentRequest: string): string | undefined {
  const decoded = bech32Words(paymentRequest);
  if (decoded === undefined || !decoded.hrp.startsWith('ln')) return undefined;
  const { words } = decoded;
  const end = words.length - SIGNATURE_WORDS;
  let position = TIMESTAMP_WORDS;
  while (position + 3 <= end) {
    const type = words[position] ?? 0;
    const length = (words[position + 1] ?? 0) * 32 + (words[position + 2] ?? 0);
    position += 3;
    if (position + length > end) return undefined;
    if (type === 1 && length === 52) {
      // 52 words are 260 bits: the 32-byte hash and 4 padding bits.
      let bits = 0n;
      for (const word of words.slice(position, position + 52)) bits = (bits << 5n) | BigInt(word);
      return (bits >> 4n).toString(16).padStart(64, '0');
    }
    position += length;
  }
  return undefined;
}

/**
 * Whether a stored payment request is damaged: not letters and digits after an
 * `ln` prefix, or a bech32 string whose checksum fails. A string that is not in
 * the bech32 alphabet at all is left undecided (false); it can still be compared
 * as text.
 */
export function damagedPaymentRequest(paymentRequest: string): boolean {
  const lower = paymentRequest.toLowerCase();
  // `ln`, letters and digits, and a `1` with at least one character after it. Checked without a regex that
  // backtracks over the position of the `1`, which took quadratic time on a long string.
  const one = lower.indexOf('1', 2);
  if (!/^ln[0-9a-z]+$/.test(lower) || one < 0 || one > lower.length - 2) return true;
  const data = lower.slice(lower.lastIndexOf('1') + 1);
  const bech32Alphabet = [...data].every(char => CHARSET.includes(char));
  return bech32Alphabet && bech32Words(paymentRequest) === undefined;
}
