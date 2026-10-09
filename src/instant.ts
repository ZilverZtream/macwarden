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
