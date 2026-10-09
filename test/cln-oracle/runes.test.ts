import { beforeAll, describe, expect, it } from 'vitest';
import { decodeRuneText, type RuneFacts } from '../../src/decode/rune.js';
import { CLN_METHODS } from '../../src/grade/cln-methods.js';
import { assessRune, methodMayPass, unixSeconds } from '../../src/grade/rune.js';
import { cli, CLN_VERSION, status } from '../fixture/cln-fixture.mjs';
import { ccanVectors, rune } from '../support/runes.js';

// Comparison of macwarden's rune decoding and assessment with a disposable regtest Core
// Lightning v26.06.8 node (test/fixture/cln-fixture.mjs). Run with:
//   npm run fixture:cln:up && npm run test:cln-oracle; npm run fixture:cln:down
// Native `decode` is the reference for parsing. `checkrune` is used only on runes this run
// created: a successful check records the rune's last use (rate and per state), so each
// rate-limited rune is checked once, first, and no rune is shared between tests.

type Native = { type?: string; unique_id?: string; version?: string; valid?: boolean; restrictions?: { alternatives: string[] }[];
  error?: { message: string } };

function ours(text: string): RuneFacts | null {
  const decoded = decodeRuneText(text);
  return decoded.ok ? decoded.facts : null;
}

/** Our alternatives in native decode's form: field, condition and unescaped value, as UTF-8. */
function shown(facts: RuneFacts): string[][] {
  return facts.restrictions.map(restriction => restriction.map(alternative =>
    Buffer.from(`${alternative.field}${alternative.condition}${alternative.value}`, 'latin1').toString('utf8')));
}

function nativeDecode(text: string): Native {
  return cli('decode', { string: text }) as Native;
}

function created(restrictions: unknown): string {
  const result = cli('createrune', { restrictions }) as { rune?: string; error?: unknown };
  if (!result.rune) throw new Error(`createrune failed: ${JSON.stringify(result.error)}`);
  return result.rune;
}

function checkrune(text: string, method: string, params: unknown = {}): boolean {
  const result = cli('checkrune', { rune: text, method, params }) as { valid?: boolean };
  return result.valid === true;
}

beforeAll(() => {
  const identity = status();
  if (!identity) throw new Error('the Core Lightning fixture is not running: npm run fixture:cln:up');
  expect(identity).toEqual({ version: CLN_VERSION, network: 'regtest' });
});

// Restrictions in createrune's JSON form: an array of restrictions, each an array of alternatives.
const POLICIES: [string, unknown][] = [
  ['single method', [['method=getinfo']]],
  ['method list', [['method=pay', 'method=keysend', 'method=xpay']]],
  ['mixed AND/OR', [['method=pay', 'method=keysend'], ['time<1800000000']]],
  ['prefix', [['method^list']]],
  ['prefix with spending', [['method^list', 'method=pay']]],
  ['exclusion', [['method/withdraw']]],
  ['contradiction', [['method=getinfo'], ['method=pay']]],
  ['every operator', [['method=getinfo', 'method/pay', 'method^list', 'method$info', 'method~fund', 'method{z', 'method}a', 'pnum<3',
    'pnum>0', 'pnamefoo!', 'note#free text']]],
  ['escaped delimiters', [['pnamelabel=a|b&c\\d'], ['method=invoice']]],
  ['peer restriction', [['id=02' + 'ab'.repeat(32)], ['method=listpeers']]],
  ['rate', [['method=getinfo'], ['rate=2']]],
  ['per', [['method=getinfo'], ['per=10sec']]],
  ['parameters', [['method=pay'], ['pnameamount_msat<100000', 'parr1<100000'], ['pinvbolt11_amount<100000']]],
  ['unknown field', [['colour=blue'], ['method=getinfo']]],
  ['expired', [['time<1600000000'], ['method=getinfo']]],
  ['expiry alternative', [['time<1600000000', 'method=getinfo']]],
  ['unicode value', [['pnamedescription=café ☕'], ['method=invoice']]],
  ['many restrictions', Array.from({ length: 40 }, (_, index) => [`pname${index}!`, 'method=getinfo'])],
];
const METHODS = ['getinfo', 'pay', 'keysend', 'xpay', 'listfunds', 'listdatastore', 'listpeers', 'invoice', 'createrune', 'withdraw',
  'fundchannel', 'summary', 'mycustomplugin-method'];

describe('RUNE/oracle native decode', () => {
  for (const [name, restrictions] of POLICIES) {
    it(`RUNE/oracle ${name}: unique ID, version and restrictions equal native decode`, () => {
      const text = created(restrictions);
      const native = nativeDecode(text);
      const facts = ours(text);
      expect(native.type).toBe('rune');
      expect(facts).not.toBeNull();
      expect(facts!.uniqueId).toBe(native.unique_id ?? null);
      expect(facts!.version).toBe(native.version ?? null);
      expect(shown(facts!)).toEqual(native.restrictions!.map(restriction => restriction.alternatives));
      expect(facts!.nonCanonical).toBe(false);
    });
  }

  it('RUNE/oracle a rune derived from another (createrune rune=…) keeps the parent restrictions first', () => {
    const parent = created([['method^list']]);
    const child = cli('createrune', { rune: parent, restrictions: [['method/listdatastore']] }) as { rune: string };
    const facts = ours(child.rune)!;
    expect(shown(facts)).toEqual(nativeDecode(child.rune).restrictions!.map(restriction => restriction.alternatives));
    expect(assessRune(facts, unixSeconds(new Date())).sensitiveMethods).not.toContain('listdatastore');
  });

  it('RUNE/oracle encodings: macwarden accepts exactly the texts native decode reads as runes', () => {
    const base = created([['method=getinfo']]);
    const unpadded = base.replace(/=+$/, '');
    const at = (text: string, index: number, character: string) => `${text.slice(0, index)}${character}${text.slice(index + 1)}`;
    const variants = [base, unpadded, `${unpadded}=`, `${unpadded}==`, `${unpadded}===`, at(base, 5, '+'), at(base, 5, '/'),
      at(base, 5, '='), unpadded.slice(0, -1), unpadded.slice(0, -2), unpadded.slice(0, -3), `${unpadded}A`,
      at(unpadded, unpadded.length - 1, String.fromCharCode(unpadded.charCodeAt(unpadded.length - 1) ^ 1)),
      rune('=1&method=getinfo&'), rune('=1&method=get\\info'), rune('=1&f=a\\'), rune('=1|f=2'), rune('f=1&=2'),
      rune('=1&f=a\0b'), rune(''), rune('='), rune('=5-v2&method=pay'), rune('=1&a b=c'),
      ...ccanVectors().filter(vector => ['VALID', 'MALFORMED', 'BAD DERIVATION'].includes(vector.kind)).map(vector => vector.fields[3])];
    for (const text of variants) {
      const native = nativeDecode(text);
      const nativeRune = native.type === 'rune';
      const facts = ours(text);
      expect(facts !== null, `${JSON.stringify(text)} native=${JSON.stringify(native)}`).toBe(nativeRune);
      if (facts && nativeRune && native.valid !== false) {
        expect(shown(facts), text).toEqual((native.restrictions ?? []).map(restriction => restriction.alternatives));
        expect(facts.uniqueId, text).toBe(native.unique_id ?? null);
        expect(facts.version, text).toBe(native.version ?? null);
      }
    }
  });

  it('RUNE/oracle invalid UTF-8 restrictions parse in both; native decode reports valid: false', () => {
    const text = rune('=1&f=\xff\xfe', Buffer.alloc(32, 7), 'latin1');
    expect(nativeDecode(text)).toMatchObject({ type: 'rune', valid: false });
    expect(ours(text)).not.toBeNull();
  });
});

describe('RUNE/oracle checkrune soundness', () => {
  for (const [name, restrictions] of POLICIES) {
    it(`RUNE/oracle ${name}: every method checkrune accepts is one macwarden may allow`, () => {
      const text = created(restrictions);
      const facts = ours(text)!;
      const assessment = assessRune(facts, unixSeconds(new Date()));
      for (const method of METHODS) {
        const accepted = checkrune(text, method);
        const mayPass = methodMayPass(facts, method);
        if (accepted) expect(mayPass, `${name}: checkrune accepted ${method}`).toBe(true);
        if (accepted && Object.hasOwn(CLN_METHODS, method) && assessment.methods === 'listed')
          expect(assessment.allowedMethods, `${name}: ${method}`).toContain(method);
        if (assessment.methods === 'none') expect(accepted, `${name}: ${method}`).toBe(false);
      }
    });
  }

  it('RUNE/oracle a passed deadline: checkrune refuses every method, macwarden reports deadline-passed', () => {
    const text = created([['time<1600000000'], ['method=getinfo']]);
    expect(assessRune(ours(text)!, unixSeconds(new Date())).expiry.status).toBe('deadline-passed');
    for (const method of METHODS) expect(checkrune(text, method), method).toBe(false);
  });

  it('RUNE/oracle time<X|method=getinfo still passes getinfo after X; macwarden does not call it expired', () => {
    const text = created([['time<1600000000', 'method=getinfo']]);
    expect(assessRune(ours(text)!, unixSeconds(new Date())).expiry.status).toBe('time-conditions');
    expect(checkrune(text, 'getinfo')).toBe(true);
    expect(checkrune(text, 'pay')).toBe(false);
  });

  it('RUNE/oracle the method table equals the commands of the pinned release', () => {
    const help = cli('help') as { help: { command: string }[] };
    const runtime = new Set(help.help.map(item => item.command.split(' ')[0]));
    const table = new Set(Object.keys(CLN_METHODS));
    expect([...runtime].filter(method => !table.has(method)), 'runtime commands missing from the table').toEqual([]);
    // clnrest-register-path exists only while clnrest runs (it needs a REST port, which the fixture does not open).
    expect([...table].filter(method => !runtime.has(method)), 'table entries the node does not offer').toEqual(['clnrest-register-path']);
  });
});
