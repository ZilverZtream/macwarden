import { createHash } from 'node:crypto';

const HASH_HEX = /^[0-9a-f]{64}$/;

/** A payment hash or preimage as 64 lowercase hex characters; anything else is refused. */
export function assertHash(value: string, what = 'payment hash'): string {
  const lower = value.toLowerCase();
  if (!HASH_HEX.test(lower)) throw new Error(`${what} must be 64 hex characters`);
  return lower;
}

/** LND's REST gateway renders `bytes` fields as standard base64. */
export function base64ToHex(value: string): string {
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(value)) throw new Error('invalid base64 field');
  return Buffer.from(value, 'base64').toString('hex');
}

export function hexToBase64(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64');
}

/**
 * Bytes in a REST path or query parameter: URL-safe base64 with padding, which
 * the gateway decodes after trying standard base64.
 */
export function hexToUrlParam(hex: string): string {
  const urlSafe = Buffer.from(hex, 'hex').toString('base64').replaceAll('+', '-').replaceAll('/', '_');
  return encodeURIComponent(urlSafe);
}

export function sha256Hex(hex: string): string {
  return createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
}

/** LND reports an absent preimage as an empty string or as 32 zero bytes. */
export function presentPreimage(hex: string): string | undefined {
  if (hex === '' || /^0+$/.test(hex)) return undefined;
  return assertHash(hex, 'payment preimage');
}
