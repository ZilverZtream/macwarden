import { ProtocolError } from './errors.ts';

/**
 * Readers for LND's REST JSON. LND marshals with proto field names, emits
 * default values and sends 64-bit integers as decimal strings. A missing field
 * reads as its proto3 default; a present field of the wrong type is refused.
 */

export type JsonObject = Record<string, unknown>;

export function asObject(value: unknown, what: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ProtocolError(`${what} is not an object`);
  return value as JsonObject;
}

export function optionalObject(source: JsonObject, key: string): JsonObject | undefined {
  const value = source[key];
  if (value === undefined || value === null) return undefined;
  return asObject(value, key);
}

export function string(source: JsonObject, key: string): string {
  const value = source[key];
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') throw new ProtocolError(`${key} is not a string`);
  return value;
}

export function boolean(source: JsonObject, key: string): boolean {
  const value = source[key];
  if (value === undefined || value === null) return false;
  if (typeof value !== 'boolean') throw new ProtocolError(`${key} is not a boolean`);
  return value;
}

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;
const UINT64_MAX = 2n ** 64n - 1n;

function anyInteger(source: JsonObject, key: string): bigint {
  const value = source[key];
  if (value === undefined || value === null || value === '') return 0n;
  if (typeof value === 'string' && /^-?(0|[1-9][0-9]{0,19})$/.test(value)) return BigInt(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
  throw new ProtocolError(`${key} is not an integer`);
}

/** A value that must fit a signed 64-bit integer (what SQLite stores); anything else is an unreadable answer. */
export function checkedInt64(value: bigint, what: string): bigint {
  if (value < INT64_MIN || value > INT64_MAX) throw new ProtocolError(`${what} is out of range`);
  return value;
}

/**
 * A (u)int64 amount, index or time, sent as a decimal string, or a number for 32-bit
 * fields. It must fit a signed 64-bit integer: the stores keep these values in SQLite,
 * which binds nothing larger, and no amount, index or time LND sends comes near 2^63.
 */
export function integer(source: JsonObject, key: string): bigint {
  return checkedInt64(anyInteger(source, key), key);
}

/** A uint64 identifier (a channel ID, which can exceed 2^63 for an alias SCID; an HTLC index), as decimal text. */
export function identifier(source: JsonObject, key: string): string {
  const value = anyInteger(source, key);
  if (value < 0n || value > UINT64_MAX) throw new ProtocolError(`${key} is out of range`);
  return value.toString();
}

export function smallInteger(source: JsonObject, key: string): number {
  const value = integer(source, key);
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) throw new ProtocolError(`${key} is out of range`);
  return Number(value);
}

export function array(source: JsonObject, key: string): unknown[] {
  const value = source[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new ProtocolError(`${key} is not an array`);
  return value;
}

/**
 * An enum field. LND sends enum names; `names` lists them in proto order so a
 * numeric rendering maps too. A name this code does not know is kept as is.
 */
export function enumName(source: JsonObject, key: string, names: readonly string[]): string {
  const value = source[key];
  if (value === undefined || value === null) return names[0] ?? '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value < names.length) return names[value] ?? '';
  throw new ProtocolError(`${key} is not an enum name`);
}
