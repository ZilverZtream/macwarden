import { describe, expect, it } from 'vitest';
import { decodeRuneText, type RuneFacts } from '../src/decode/rune.js';
import { CLN_METHODS, CLN_RELEASE, CLN_SENSITIVE } from '../src/grade/cln-methods.js';
import { assessRune, methodClass, RUNE_METHOD_TABLE, unixSeconds } from '../src/grade/rune.js';
import { runeReport, shownRuneText } from '../src/rune-report.js';
import { rune } from './support/runes.js';

// docs/spec.md, Core Lightning runes > Assessment. A capability is excluded only when the whole
// restriction structure proves no request for it can pass; request-dependent conditions are unknown.

const NOW = 1_790_000_000n; // 2026-09-21
function facts(text: string): RuneFacts {
  const decoded = decodeRuneText(rune(text));
  if (!decoded.ok) throw new Error(decoded.reason);
  return decoded.facts;
}
const assess = (text: string, now = NOW) => assessRune(facts(text), now);

describe('RUNE/assess acceptance table of the design brief', () => {
  it('RUNE/assess method=getinfo is READ under the reviewed table', () => {
    expect(assess('=1&method=getinfo')).toMatchObject({ grade: 'READ', reasons: ['getinfo'], methods: 'listed',
      allowedMethods: ['getinfo'], capabilities: ['READ'], unreviewedMethods: [], warnings: [] });
  });

  it('RUNE/assess method=pay is SPEND', () => {
    expect(assess('=1&method=pay')).toMatchObject({ grade: 'SPEND', reasons: ['pay'], methods: 'listed', capabilities: ['SPEND'] });
  });

  it('RUNE/assess method^list is UNASSESSED with a broad-access warning, and listdatastore is surfaced as sensitive', () => {
    const result = assess('=1&method^list');
    expect(result.grade).toBe('UNASSESSED');
    expect(result.methods).toBe('broad');
    expect(result.warnings).toEqual(expect.arrayContaining(['broad-method-access', 'sensitive-method']));
    expect(result.sensitiveMethods).toEqual(expect.arrayContaining(['listconfigs', 'listdatastore']));
    expect(result.capabilities).toEqual(['READ', 'UNASSESSED']);
  });

  it('RUNE/assess method^list|method=pay is UNASSESSED with possible spending surfaced', () => {
    const result = assess('=1&method^list|method=pay');
    expect(result.grade).toBe('UNASSESSED');
    expect(result.capabilities).toContain('SPEND');
    expect(result.capabilities[0]).toBe('SPEND');
  });

  it('RUNE/assess method/withdraw is broad access: excluding one spending method leaves ADMIN and SPEND possible', () => {
    const result = assess('=1&method/withdraw');
    expect(result.grade).toBe('ADMIN');
    expect(result.methods).toBe('broad');
    expect(result.capabilities).toEqual(['ADMIN', 'SPEND', 'OPERATE', 'RECEIVE', 'READ', 'UNASSESSED']);
    expect(result.reasons).toContain('createrune');
    expect(result.warnings).toContain('broad-method-access');
  });

  it('RUNE/assess method=getinfo&method=pay is contradictory: no method can pass', () => {
    const result = assess('=1&method=getinfo&method=pay');
    expect(result).toMatchObject({ methods: 'none', allowedMethods: [], capabilities: [], reasons: [], grade: 'READ' });
    expect(result.warnings).toContain('no-matching-method');
  });
});

describe('RUNE/assess structure', () => {
  it('RUNE/assess an unrestricted rune can call every method: ADMIN, broad', () => {
    expect(assess('=1')).toMatchObject({ grade: 'ADMIN', methods: 'broad' });
    expect(assess('')).toMatchObject({ grade: 'ADMIN', methods: 'broad' });
  });

  it('RUNE/assess mixed AND/OR: the pinned sets of several restrictions intersect', () => {
    expect(assess('=1&method=pay|method=getinfo&method=getinfo|method=listfunds')).toMatchObject({
      grade: 'READ', allowedMethods: ['getinfo'] });
    expect(assess('=1&method=pay|method=keysend&time<1800000000')).toMatchObject({ grade: 'SPEND', allowedMethods: ['keysend', 'pay'] });
  });

  it('RUNE/assess a method alternative joined with a request-dependent one is not a pin', () => {
    const result = assess('=1&method=getinfo|id=02' + 'ab'.repeat(32));
    expect(result.methods).toBe('broad');
    expect(result.grade).toBe('ADMIN');
    expect(result.conditions).toEqual(['peer']);
  });

  it('RUNE/assess a pinned method the table does not list is unreviewed: UNASSESSED', () => {
    const result = assess('=1&method=myplugin-dosomething|method=getinfo');
    expect(result).toMatchObject({ grade: 'UNASSESSED', methods: 'listed', allowedMethods: ['getinfo'],
      unreviewedMethods: ['myplugin-dosomething'] });
    expect(result.warnings).toContain('unreviewed-method');
    // ADMIN still wins over unreviewed names.
    expect(assess('=1&method=myplugin|method=createrune').grade).toBe('ADMIN');
  });

  it('RUNE/assess exclusions and prefixes evaluate exact table names', () => {
    const result = assess('=1&method^list&method/listdatastore&method/listconfigs');
    expect(result.grade).toBe('UNASSESSED');
    expect(result.capabilities).toEqual(['READ']);
    expect(result.sensitiveMethods).toEqual([]);
    expect(assess('=1&method$pay&method^x').capabilities).toEqual(['SPEND']);
  });

  it('RUNE/assess comment alternatives always pass; a comment never restricts', () => {
    expect(assess('=1&method=getinfo|comment#note').methods).toBe('broad');
    expect(assess('=1&comment#note&method=getinfo')).toMatchObject({ grade: 'READ', methods: 'listed' });
  });

  it('RUNE/assess conditions that can never hold are false for every request', () => {
    // method is a string field, so < and > fail; time is always present, so ! fails.
    expect(assess('=1&method<5|method=getinfo').allowedMethods).toEqual(['getinfo']);
    expect(assess('=1&time!|method=getinfo').methods).toBe('listed');
    expect(assess('=1&time<abc').methods).toBe('none');
    expect(assess('=1&id>3').methods).toBe('none');
  });

  it('RUNE/assess rate and per are request state: valid ones are unknown, malformed ones always fail', () => {
    expect(assess('=1&rate=60&method=pay')).toMatchObject({ grade: 'SPEND', conditions: ['rate'] });
    for (const bad of ['rate=0', 'rate=4294967295', 'rate/5', 'rate=5x', 'rate#5', 'per=0', 'per=5fortnight', 'per=4294967294day'])
      expect(assess(`=1&${bad}`).methods, bad).toBe('none');
    for (const good of ['per=5', 'per=5sec', 'per=10min', 'per=1day', 'per=100msec', 'per= +7hour'])
      expect(assess(`=1&${good}&method=getinfo`).grade, good).toBe('READ');
  });

  it('RUNE/assess invoice fields: known suffixes are unknown, others always fail', () => {
    expect(assess('=1&method=pay&pinvbolt11_amount<1000').conditions).toEqual(['parameter']);
    expect(assess('=1&pinvbolt11_weird=1').methods).toBe('none');
  });

  it('RUNE/assess peer, parameter and rate restrictions are described, and do not lower a spending grade', () => {
    const result = assess('=1&method=pay&id=02' + 'cd'.repeat(32) + '&pnameamount_msat<10000&rate=1');
    expect(result.grade).toBe('SPEND');
    expect(result.conditions).toEqual(['parameter', 'peer', 'rate']);
    expect(result.warnings).toContain('parameter-limits-not-a-budget');
  });

  it('RUNE/assess an unknown field is an assessment limitation and never excludes a method', () => {
    const result = assess('=1&colour=blue&method=getinfo');
    expect(result).toMatchObject({ grade: 'READ', conditions: ['unknown-field'] });
    expect(result.warnings).toContain('unknown-field');
    expect(assess('=1&colour=blue').methods).toBe('broad');
  });

  it('RUNE/assess sensitive reads are named with the reason from the table', () => {
    const result = assess('=1&method=listdatastore');
    expect(result).toMatchObject({ grade: 'UNASSESSED', sensitiveMethods: ['listdatastore'], capabilities: ['UNASSESSED'] });
    expect(assess('=1&method=listconfigs')).toMatchObject({ grade: 'READ', sensitiveMethods: ['listconfigs'] });
    expect(assess('=1&method=showrunes').grade).toBe('ADMIN');
  });
});

describe('RUNE/expiry status', () => {
  it('RUNE/expiry a single deadline in the past is passed according to the local clock; the grade is kept', () => {
    const result = assess('=1&method=pay&time<1700000000');
    expect(result.expiry).toEqual({ status: 'deadline-passed', deadline: '1700000000' });
    expect(result.grade).toBe('SPEND');
  });

  it('RUNE/expiry time<X|method=pay is not expired: pay still passes after X', () => {
    expect(assess('=1&time<1700000000|method=pay').expiry).toEqual({ status: 'time-conditions', deadline: null });
  });

  it('RUNE/expiry the earliest closing restriction decides; alternatives within one take the latest', () => {
    expect(assess('=1&time<1700000000|time<1800000000&time<1900000000').expiry).toEqual({ status: 'deadline-ahead', deadline: '1800000000' });
    expect(assess('=1&time<1800000000', 1_800_000_000n).expiry.status).toBe('deadline-passed');
    expect(assess('=1&time<1800000000', 1_799_999_999n).expiry.status).toBe('deadline-ahead');
  });

  it('RUNE/expiry a lower bound or an equality never closes the rune', () => {
    expect(assess('=1&time>1700000000').expiry.status).toBe('time-conditions');
    expect(assess('=1&time=1700000000').expiry.status).toBe('time-conditions');
    expect(assess('=1&method=pay').expiry).toEqual({ status: 'none', deadline: null });
  });

  it('RUNE/expiry an invalid deadline value is not a deadline', () => {
    expect(assess('=1&time<soon|method=pay').expiry.status).toBe('time-conditions');
  });

  it('RUNE/expiry clock conversion is integer-safe and rounds down', () => {
    expect(unixSeconds(new Date(1_799_999_999_999))).toBe(1_799_999_999n);
    expect(unixSeconds(new Date(-1))).toBe(-1n);
    expect(unixSeconds(new Date(8.64e15))).toBe(8_640_000_000_000n);
  });
});

describe('RUNE/identity unique ID warnings predict how checkrune treats the rune', () => {
  it('RUNE/identity numeric IDs are clean; missing, non-numeric, out-of-range and versioned ones warn', () => {
    expect(assess('=17&method=getinfo').warnings).toEqual([]);
    expect(assess('method=getinfo').warnings).toContain('no-unique-id');
    expect(assess('=abc&method=getinfo').warnings).toContain('unique-id-not-numeric');
    // Core Lightning splits the ID restriction at its first '-': "=-1" is an empty ID with version "1".
    expect(assess('=-1&method=getinfo').warnings).toContain('version-suffix');
    expect(assess('=-1&method=getinfo').warnings).not.toContain('unique-id-not-numeric');
    expect(assess('=9223372036854775808&method=getinfo').warnings).toContain('unique-id-not-numeric');
    expect(assess('=100000000&method=getinfo').warnings).toContain('unique-id-out-of-range');
    expect(assess('=99999999&method=getinfo').warnings).toEqual([]);
    expect(assess('=4-2&method=getinfo').warnings).toContain('version-suffix');
    expect(assess('=&method=getinfo').warnings).toEqual([]);
  });
});

describe('RUNE/table the method table is pinned and complete', () => {
  it('RUNE/table names its release and gives every method a grade', () => {
    expect(CLN_RELEASE).toBe('v26.06.8');
    expect(RUNE_METHOD_TABLE).toBe('cln-v26.06.8');
    const grades = new Set(['ADMIN', 'SPEND', 'OPERATE', 'RECEIVE', 'READ', 'UNASSESSED']);
    expect(Object.keys(CLN_METHODS).length).toBe(211);
    for (const [method, grade] of Object.entries(CLN_METHODS)) expect(grades.has(grade), method).toBe(true);
    for (const method of Object.keys(CLN_SENSITIVE)) expect(methodClass(method), method).toBeDefined();
  });

  it('RUNE/table rune administration and secret export are ADMIN; payments SPEND', () => {
    for (const method of ['createrune', 'invokerune', 'blacklistrune', 'destroyrune', 'showrunes', 'exposesecret', 'makesecret', 'plugin', 'setconfig', 'commando'])
      expect(methodClass(method), method).toBe('ADMIN');
    for (const method of ['pay', 'xpay', 'keysend', 'withdraw', 'sendpay', 'fundchannel', 'close', 'signpsbt', 'txsend'])
      expect(methodClass(method), method).toBe('SPEND');
    expect(methodClass('invoice')).toBe('RECEIVE');
    expect(methodClass('getinfo')).toBe('READ');
    expect(methodClass('checkrune')).toBe('OPERATE');
    expect(methodClass('nosuchmethod')).toBeUndefined();
  });
});

describe('RUNE/report sanitised output facts', () => {
  it('RUNE/report long opaque values are redacted, node IDs kept, length bounded', () => {
    const nodeId = '03' + 'ef'.repeat(32);
    expect(shownRuneText(nodeId)).toBe(nodeId);
    expect(shownRuneText(`x ${'A'.repeat(50)} y`)).toBe('x [redacted] y');
    expect(shownRuneText('lnbcrt10u1' + 'q'.repeat(60))).toBe('[redacted]');
    const long = shownRuneText('a b '.repeat(100));
    expect([...long].length).toBeLessThan(150);
    expect(long).toMatch(/…\[\+\d+\]$/);
    expect(shownRuneText('caf\xe9')).toBe('caf\\xe9');
    expect(shownRuneText(Buffer.from('café').toString('latin1'))).toBe('café');
  });

  it('RUNE/report lists at most 64 alternatives and counts the rest', () => {
    const many = Array.from({ length: 80 }, (_, index) => `method=m${index}`).join('|');
    const { report } = runeReport(facts(`=1&${many}`), NOW);
    expect(report.restrictions.flat()).toHaveLength(64);
    expect(report.omittedAlternatives).toBe(16);
  });

  it('RUNE/report a possibly truncated rune is never graded below UNASSESSED, except ADMIN', () => {
    expect(runeReport(facts('=1&method=getinfo'), NOW, true)).toMatchObject({ grade: 'UNASSESSED', reasons: [] });
    expect(runeReport(facts('=1&method=getinfo'), NOW, true).report.warnings).toContain('possibly-truncated');
    expect(runeReport(facts('=1'), NOW, true).grade).toBe('ADMIN');
  });

  it('RUNE/report never contains the authenticator', () => {
    const text = '=1&method=getinfo';
    const { report } = runeReport(facts(text), NOW);
    const json = JSON.stringify(report);
    for (const form of [Buffer.alloc(32, 0x5a).toString('hex'), Buffer.alloc(32, 0x5a).toString('base64url').slice(0, 40), 'ZZZZZZZZ'])
      expect(json.includes(form), form).toBe(false);
    expect(report.verification).toBe('unchecked');
    expect(report.recognition).toBe('rune-syntax');
  });
});
