import type { L402Caveat, L402Facts } from './decode/index.js';

// What an L402 credential grants, judged offline from decoded facts and a clock, the way
// Aperture judges it (lightninglabs/aperture l402/service.go, l402/satisfier.go). Pure.

export type L402ReportCaveat = L402Caveat & { expired?: boolean; until?: string };
export type L402Status = 'live' | 'expired' | 'preimage-mismatch' | 'unpaid';
/** The L402 facts inspect and scan report. An L402 token grants access to a paid service, never control of a node. */
export type L402Report = {
  form: L402Facts['form'];
  scheme: L402Facts['scheme'];
  macaroonFingerprint: string;
  macaroons: number;
  location: string | null;
  identifier: L402Facts['identifier'];
  services: { name: string; tier: string }[];
  caveats: L402ReportCaveat[];
  preimage: L402Facts['preimage'];
  preimageSource: L402Facts['preimageSource'];
  status: L402Status;
  expired: boolean;
  access: 'service-access';
  countedAs: 'READ' | null;
  warnings: string[];
};

const INT64_MIN = -(1n << 63n);
const INT64_MAX = (1n << 63n) - 1n;
// JavaScript dates reach 8.64e15 ms either side of the epoch.
const DATE_LIMIT_SECONDS = 8_640_000_000_000n;

/** Digits of the int64 range (9223372036854775807) after leading zeros; longer is out of range. */
const INT64_DIGITS = 19;

/**
 * A _valid_until value as Go's strconv.ParseInt(value, 10, 64) reads it, else undefined. Go
 * accepts any number of leading zeros, so only the significant digits are bounded.
 */
export function parseValidUntil(value: string): bigint | undefined {
  if (!/^[+-]?[0-9]+$/.test(value) || value.replace(/^[+-]?0*/, '').length > INT64_DIGITS) return undefined;
  const seconds = BigInt(value);
  return seconds < INT64_MIN || seconds > INT64_MAX ? undefined : seconds;
}

/** Aperture's decodeServicesCaveatValue: "name:tier" items joined by ","; tier as strconv.Atoi reads it. */
function parseServices(value: string): { name: string; tier: string }[] | null {
  if (value === '') return null;
  const services: { name: string; tier: string }[] = [];
  for (const item of value.split(',')) {
    const parts = item.split(':');
    if (parts.length !== 2 || parts[0] === '' || parseValidUntil(parts[1]) === undefined) return null;
    services.push({ name: parts[0], tier: parts[1] });
  }
  return services;
}

function byteSort(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

/**
 * Services, expiry and status. A `<service>_valid_until` caveat holds Unix seconds; Aperture
 * accepts the token while now is before that instant, and decides with the last such caveat
 * for a service. The token is expired when the last services caveat names at least one service
 * and the last valid-until caveat of every named service has passed.
 */
export function assessL402(facts: L402Facts, now: Date): L402Report {
  const warnings = [...facts.warnings];
  const nowMs = BigInt(now.getTime());
  const caveats: L402ReportCaveat[] = facts.caveats.map(caveat => {
    if (caveat.type !== 'valid-until' || caveat.value === null) return caveat;
    const seconds = parseValidUntil(caveat.value);
    if (seconds === undefined) { warnings.push('l402-bad-valid-until'); return caveat; }
    const until = seconds >= -DATE_LIMIT_SECONDS && seconds <= DATE_LIMIT_SECONDS
      ? { until: new Date(Number(seconds) * 1000).toISOString().replace(/\.000Z$/, 'Z') } : {};
    return { ...caveat, ...until, expired: nowMs >= seconds * 1000n };
  });
  let services: { name: string; tier: string }[] = [];
  const lastServices = caveats.filter(caveat => caveat.type === 'services').at(-1);
  if (lastServices) {
    const parsed = parseServices(lastServices.value ?? '');
    if (parsed === null) warnings.push('l402-bad-services'); else services = parsed;
  }
  const expired = services.length > 0 && services.every(service => {
    const last = caveats.filter(caveat => caveat.type === 'valid-until' && caveat.service === service.name).at(-1);
    return last?.expired === true;
  });
  const paid = facts.preimage === 'matches' || facts.preimage === 'unverifiable';
  const status: L402Status = facts.preimage === 'absent' ? 'unpaid' : facts.preimage === 'mismatch' ? 'preimage-mismatch'
    : expired ? 'expired' : 'live';
  return {
    form: facts.form, scheme: facts.scheme, macaroonFingerprint: facts.macaroonFingerprint, macaroons: facts.macaroons, location: facts.location,
    identifier: facts.identifier, services, caveats, preimage: facts.preimage, preimageSource: facts.preimageSource,
    status, expired, access: 'service-access', countedAs: paid ? 'READ' : null, warnings: byteSort(warnings),
  };
}
