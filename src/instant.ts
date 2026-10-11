// UTC instants as macwarden writes them (Date.prototype.toISOString, or the same without the
// fraction), read back from the registry and the watch usage file.

const SHAPE = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?Z$/;

function daysIn(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/**
 * True for `YYYY-MM-DDTHH:MM:SS[.fraction]Z` naming a real instant: a month 1 to 12, a day that
 * exists in that month, hours 0 to 23, minutes and seconds 0 to 59. The shape alone is not
 * enough: Date.parse gives NaN for month 99 and silently rolls 30 February or 24:00 into
 * another day, and either would corrupt time arithmetic on the value.
 */
export function isInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = SHAPE.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  return month >= 1 && month <= 12 && day >= 1 && day <= daysIn(year, month)
    && hour <= 23 && minute <= 59 && second <= 59 && Number.isFinite(Date.parse(value));
}

/**
 * The later of two instants, compared as instants: as text, `…:00Z` sorts after the later
 * `…:00.900Z`. Keeps `a` on a tie; a value Date.parse cannot read never wins over one it can.
 */
export function laterInstant(a: string, b: string): string {
  const left = Date.parse(a), right = Date.parse(b);
  if (Number.isNaN(right)) return a;
  if (Number.isNaN(left)) return b;
  return right > left ? b : a;
}

/** Unix nanoseconds of 0000-01-01T00:00:00Z and of 10000-01-01T00:00:00Z: RFC 3339 has four-digit years only. */
const FIRST_NS = -62_167_219_200n * 1_000_000_000n;
const END_NS = 253_402_300_800n * 1_000_000_000n;

/**
 * An instant given in Unix nanoseconds as `YYYY-MM-DDThh:mm:ssZ` (the fraction dropped), or
 * null when it lies outside the years 0000 to 9999 that RFC 3339 can write.
 */
export function secondsInstant(nanoseconds: bigint): string | null {
  if (nanoseconds < FIRST_NS || nanoseconds >= END_NS) return null;
  const remainder = nanoseconds % 1_000_000_000n;
  const seconds = nanoseconds / 1_000_000_000n - (remainder < 0n ? 1n : 0n);
  return new Date(Number(seconds) * 1_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}
