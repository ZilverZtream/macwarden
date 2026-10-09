// Conservative policy assessment of a Core Lightning rune (1.2.0), offline. It never tells
// whether a node would accept the rune (authenticity, issuing node, blacklist and rate-limit
// state stay unchecked); it tells which reviewed methods its encoded restrictions could let
// through. The governing rule: a capability is excluded only when the complete restriction
// structure proves that no request for it can pass. Conditions that depend on the request
// (peer, parameters, rate, time) are unknown, so they never exclude anything.
//
// Field semantics follow Core Lightning v26.06.8 lightningd/runes.c (check_condition) and
// ccan/ccan/rune/rune.c (rune_alt_single); the method table is pinned to the same release.
import type { RuneAlternative, RuneFacts } from '../decode/rune.js';
import type { Grade } from './index.js';
import { CLN_METHODS as METHODS, CLN_RELEASE, CLN_SENSITIVE as SENSITIVE } from './cln-methods.js';

/** The method table's version: the Core Lightning release it was reviewed against. */
export const RUNE_METHOD_TABLE = `cln-${CLN_RELEASE}`;
const LADDER: readonly Grade[] = ['READ', 'RECEIVE', 'OPERATE', 'SPEND', 'ADMIN'];

export type RuneConditionKind = 'peer' | 'parameter' | 'rate' | 'time' | 'unknown-field';
export type RuneExpiry = {
  /** none: no time condition; time-conditions: some, but they do not close every request;
   * deadline-ahead / deadline-passed: every request is rejected from `deadline` on (UNIX seconds). */
  status: 'none' | 'time-conditions' | 'deadline-ahead' | 'deadline-passed';
  deadline: string | null;
};
export type RuneWarning = 'broad-method-access' | 'unreviewed-method' | 'sensitive-method' | 'no-matching-method'
  | 'unknown-field' | 'parameter-limits-not-a-budget' | 'no-unique-id' | 'unique-id-not-numeric'
  | 'unique-id-out-of-range' | 'version-suffix' | 'non-canonical-encoding';
export type RuneAssessment = {
  grade: Grade;
  /** The reviewed methods whose class equals the grade (empty for UNASSESSED). */
  reasons: string[];
  /** listed: the restrictions pin the method to a finite set of exact names; broad: they do not;
   * none: no method can pass. */
  methods: 'listed' | 'broad' | 'none';
  /** Reviewed methods that may be allowed, when `methods` is listed. */
  allowedMethods: string[];
  /** The classes of every reviewed method that may be allowed, highest first. */
  capabilities: Grade[];
  /** Method names the restrictions allow by exact name that the table does not list. */
  unreviewedMethods: string[];
  sensitiveMethods: string[];
  conditions: RuneConditionKind[];
  expiry: RuneExpiry;
  warnings: RuneWarning[];
};

const FALSE = 0, TRUE = 1, UNKNOWN = 2;
type Tri = typeof FALSE | typeof TRUE | typeof UNKNOWN;

const LONG_MIN = -(2n ** 63n), LONG_MAX = 2n ** 63n - 1n, ULONG_MAX = 2n ** 64n - 1n;

/** strtol(value, &end, 10) on a 64-bit long, accepted only when it consumes everything without overflow. */
export function runeInteger(value: string): bigint | null {
  const match = /^[ \t\n\v\f\r]*([+-]?)([0-9]+)$/.exec(value);
  if (!match) return null;
  const magnitude = BigInt(match[2]);
  const number = match[1] === '-' ? -magnitude : magnitude;
  return number < LONG_MIN || number > LONG_MAX ? null : number;
}

function bytesCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'latin1'), Buffer.from(right, 'latin1'));
}

/** rune_alt_single for a string field value that is present. */
function stringTest(alternative: RuneAlternative, field: string): boolean {
  const { condition, value } = alternative;
  switch (condition) {
    case '!': return false;
    case '=': return field === value;
    case '/': return field !== value;
    case '^': return field.startsWith(value);
    case '$': return field.endsWith(value);
    case '~': return field.includes(value);
    case '<': case '>': return false; // "is not an integer field"
    case '{': return bytesCompare(field, value) < 0;
    case '}': return bytesCompare(field, value) > 0;
    case '#': return true;
  }
}

/** rune_alt_single for an integer field value: compared as integers for < and >, else as its decimal text. */
function integerTest(alternative: RuneAlternative, field: bigint): boolean {
  const { condition, value } = alternative;
  if (condition === '<' || condition === '>') {
    const bound = runeInteger(value);
    return bound !== null && (condition === '<' ? field < bound : field > bound);
  }
  return stringTest(alternative, field.toString());
}

/** strtoul(value, &end, 10) on a 64-bit unsigned long: a negative number wraps modulo 2^64, overflow gives ULONG_MAX. */
function strtoul(value: string): { number: bigint; rest: string } | null {
  const match = /^[ \t\n\v\f\r]*([+-]?)([0-9]+)(.*)$/s.exec(value);
  if (!match) return null;
  const magnitude = BigInt(match[2]);
  const number = magnitude > ULONG_MAX ? ULONG_MAX : match[1] === '-' && magnitude !== 0n ? ULONG_MAX + 1n - magnitude : magnitude;
  return { number, rest: match[3] };
}

/** per_time_check's units, in nanoseconds. */
const PER_UNITS: ReadonlyMap<string, bigint> = new Map([['', 1_000_000_000n], ['sec', 1_000_000_000n], ['nsec', 1n], ['usec', 1000n],
  ['msec', 1_000_000n], ['min', 60_000_000_000n], ['hour', 3_600_000_000_000n], ['day', 86_400_000_000_000n]]);

/** True when a strtoul-style rate or per value is one Core Lightning accepts. */
function validRate(alternative: RuneAlternative, per: boolean): boolean {
  if (alternative.condition !== '=') return false;
  const parsed = strtoul(alternative.value);
  if (!parsed) return false;
  const { number, rest } = parsed;
  if (number === 0n || number >= 0xffffffffn) return false;
  if (!per) return rest === '';
  // A Map, not an object literal: a unit such as "constructor" must not find an inherited property.
  const multiplier = PER_UNITS.get(rest);
  return multiplier !== undefined && number * multiplier < 2n ** 64n;
}

/**
 * rune_alt_single: whether one alternative passes for a field that is missing (null), an integer
 * field (bigint) or a string field (string). checkrune passes parameters that parse as integers
 * as integers, so an integer and its decimal text differ only for '<' and '>'.
 */
export function alternativeHolds(alternative: RuneAlternative, field: string | bigint | null): boolean {
  if (field === null) return alternative.condition === '!' || alternative.condition === '#';
  return typeof field === 'bigint' ? integerTest(alternative, field) : stringTest(alternative, field);
}

const INVOICE_FIELDS = ['_amount', '_description', '_node'];

/** The class of request-dependent condition a field is, or null for method. */
function conditionKind(field: string): RuneConditionKind | null {
  if (field === 'method') return null;
  if (field === 'time') return 'time';
  if (field === 'id') return 'peer';
  if (field === 'rate' || field === 'per') return 'rate';
  if (field === 'pnum' || field.startsWith('pname') || field.startsWith('parr') || field.startsWith('pinv')) return 'parameter';
  return 'unknown-field';
}

/**
 * One alternative for a request calling `method` (null: some method the table does not list)
 * at an unknown time (now null) or at `now` (UNIX seconds). Only facts that hold for every
 * request decide; everything that depends on the request is UNKNOWN.
 */
function evaluate(alternative: RuneAlternative, method: string | null, now: bigint | null): Tri {
  const { field, condition } = alternative;
  const integerShape = (): Tri => (condition === '<' || condition === '>') && runeInteger(alternative.value) === null ? FALSE
    : condition === '!' ? FALSE : condition === '#' ? TRUE : UNKNOWN;
  switch (field) {
    case 'method':
      // commando and clnrest always name the method, so it is present.
      if (method !== null) return stringTest(alternative, method) ? TRUE : FALSE;
      return condition === '<' || condition === '>' || condition === '!' ? FALSE : condition === '#' ? TRUE : UNKNOWN;
    case 'time':
      if (now !== null) return integerTest(alternative, now) ? TRUE : FALSE;
      return integerShape();
    case 'pnum':
      return integerShape();
    case 'id':
      // The peer's node ID is a string, and absent for a local call.
      return condition === '<' || condition === '>' ? FALSE : condition === '#' ? TRUE : UNKNOWN;
    case 'rate': case 'per':
      // Even a comment fails here: Core Lightning checks rate and per before the condition.
      return validRate(alternative, field === 'per') ? UNKNOWN : FALSE;
  }
  if (field.startsWith('pinv')) return INVOICE_FIELDS.some(suffix => field.endsWith(suffix)) ? UNKNOWN : FALSE;
  // Parameters, and fields this release does not know (kept as an assessment limitation).
  return condition === '#' ? TRUE : UNKNOWN;
}

function restrictionValue(restriction: RuneAlternative[], method: string | null, now: bigint | null): Tri {
  let result: Tri = FALSE;
  for (const alternative of restriction) {
    const value = evaluate(alternative, method, now);
    if (value === TRUE) return TRUE;
    if (value === UNKNOWN) result = UNKNOWN;
  }
  return result;
}

function possible(restrictions: RuneAlternative[][], method: string | null): boolean {
  return restrictions.every(restriction => restrictionValue(restriction, method, null) !== FALSE);
}

/** The exact method names a restriction admits, or null when it admits more than a finite set. */
function pinnedMethods(restriction: RuneAlternative[]): Set<string> | null {
  const names = new Set<string>();
  for (const alternative of restriction) {
    if (alternative.field === 'method' && alternative.condition === '=') names.add(alternative.value);
    else if (evaluate(alternative, null, null) !== FALSE) return null;
  }
  return names;
}

function byteSort(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => bytesCompare(left, right));
}

function expiry(restrictions: RuneAlternative[][], now: bigint): RuneExpiry {
  let deadline: bigint | null = null;
  let timed = false;
  for (const restriction of restrictions) {
    let closes: bigint | null = null;
    let open = false;
    for (const alternative of restriction) {
      if (alternative.field === 'time') timed = true;
      const bound = alternative.field === 'time' && alternative.condition === '<' ? runeInteger(alternative.value) : null;
      if (bound !== null) closes = closes === null || bound > closes ? bound : closes;
      else if (evaluate(alternative, null, null) !== FALSE) open = true;
    }
    if (!open && closes !== null && (deadline === null || closes < deadline)) deadline = closes;
  }
  if (deadline !== null) return { status: now >= deadline ? 'deadline-passed' : 'deadline-ahead', deadline: deadline.toString() };
  return { status: timed ? 'time-conditions' : 'none', deadline: null };
}

/** Warnings about the unique ID and encoding that predict how Core Lightning's checkrune treats the rune. */
function identityWarnings(facts: RuneFacts): RuneWarning[] {
  const warnings: RuneWarning[] = [];
  if (facts.nonCanonical) warnings.push('non-canonical-encoding');
  if (facts.version !== null) warnings.push('version-suffix');
  if (facts.uniqueId === null) { warnings.push('no-unique-id'); return warnings; }
  const value = runeUniqueIdNumber(facts.uniqueId);
  if (value === null) warnings.push('unique-id-not-numeric');
  // is_rune_blacklisted: IDs from 100,000,000 on cannot be blacklisted and are always refused.
  else if (value >= 100_000_000n) warnings.push('unique-id-out-of-range');
  return warnings;
}

/**
 * param_rune's unique_id_num: strtoull over the whole unique ID, accepted only up to INT64_MAX
 * ("" reads as 0). Null when checkrune refuses the rune as having no valid numeric unique ID.
 */
export function runeUniqueIdNumber(uniqueId: string): bigint | null {
  if (uniqueId === '') return 0n;
  const match = /^[ \t\n\v\f\r]*([+-]?)([0-9]+)$/.exec(uniqueId);
  if (!match) return null;
  const magnitude = BigInt(match[2]);
  if (magnitude > ULONG_MAX) return null;
  const value = match[1] === '-' && magnitude !== 0n ? ULONG_MAX + 1n - magnitude : magnitude;
  return value > LONG_MAX ? null : value;
}

export function assessRune(facts: RuneFacts, nowSeconds: bigint): RuneAssessment {
  const { restrictions } = facts;
  const warnings = new Set<RuneWarning>(identityWarnings(facts));
  const conditions = new Set<RuneConditionKind>();
  for (const restriction of restrictions)
    for (const alternative of restriction) {
      const kind = conditionKind(alternative.field);
      if (kind) conditions.add(kind);
    }
  if (conditions.has('unknown-field')) warnings.add('unknown-field');

  // Finite method sets, intersected over every restriction that pins the method.
  let listed: Set<string> | null = null;
  for (const restriction of restrictions) {
    const pinned = pinnedMethods(restriction);
    if (pinned) {
      const previous: Set<string> | null = listed;
      listed = previous === null ? pinned : new Set([...previous].filter((name: string) => pinned.has(name)));
    }
  }
  const candidates = listed === null ? Object.keys(METHODS) : [...listed];
  const allowed = byteSort(candidates.filter(name => possible(restrictions, name)));
  const reviewed = allowed.filter(name => Object.hasOwn(METHODS, name));
  const unreviewed = allowed.filter(name => !Object.hasOwn(METHODS, name));
  // Without a pinned set any method name could pass unless a restriction rejects every method.
  const broad = listed === null && possible(restrictions, null);
  if (broad) warnings.add('broad-method-access');
  if (unreviewed.length) warnings.add('unreviewed-method');
  const sensitive = reviewed.filter(name => Object.hasOwn(SENSITIVE, name));
  if (sensitive.length) warnings.add('sensitive-method');

  const classes = new Set(reviewed.map(name => METHODS[name]));
  const capabilities = [...LADDER].reverse().filter(grade => classes.has(grade));
  if (classes.has('UNASSESSED')) capabilities.push('UNASSESSED');
  const highest = capabilities.find(grade => grade !== 'UNASSESSED');
  const methods = broad ? 'broad' : allowed.length ? 'listed' : 'none';
  let grade: Grade;
  if (methods === 'none') {
    // Nothing can pass: reported at the lowest grade, never omitted (see docs/spec.md).
    warnings.add('no-matching-method');
    grade = 'READ';
  } else if ((broad || unreviewed.length || classes.has('UNASSESSED')) && highest !== 'ADMIN') grade = 'UNASSESSED';
  else grade = highest ?? 'UNASSESSED';
  if (conditions.has('parameter') && (classes.has('SPEND') || classes.has('ADMIN') || broad)) warnings.add('parameter-limits-not-a-budget');
  return {
    grade,
    reasons: grade === 'UNASSESSED' || methods === 'none' ? [] : reviewed.filter(name => METHODS[name] === grade),
    methods,
    allowedMethods: methods === 'listed' ? reviewed : [],
    capabilities,
    unreviewedMethods: unreviewed,
    sensitiveMethods: sensitive,
    conditions: byteSort(conditions) as RuneConditionKind[],
    expiry: expiry(restrictions, nowSeconds),
    warnings: byteSort(warnings) as RuneWarning[],
  };
}

/**
 * Whether a request for `method` may pass every restriction: false only when the restrictions
 * prove that no request for it can pass (the comparison tests check this against checkrune).
 */
export function methodMayPass(facts: RuneFacts, method: string): boolean {
  return possible(facts.restrictions, method);
}

/** The class the pinned table gives a method, or undefined when it does not list it. */
export function methodClass(method: string): Grade | undefined {
  return Object.hasOwn(METHODS, method) ? METHODS[method] : undefined;
}

/** Why a reviewed method is sensitive, when it is. */
export function sensitiveReason(method: string): string | undefined {
  return Object.hasOwn(SENSITIVE, method) ? SENSITIVE[method] : undefined;
}

/** Seconds since the UNIX epoch, rounded down, from a clock reading (integer-safe). */
export function unixSeconds(now: Date): bigint {
  const ms = BigInt(now.getTime());
  return ms >= 0n ? ms / 1000n : -((-ms + 999n) / 1000n);
}
