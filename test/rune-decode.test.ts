import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeRuneBase64, decodeRuneText, RUNE_ALTERNATIVE_LIMIT, RUNE_RESTRICTION_LIMIT, RUNE_TEXT_LIMIT,
  type RuneAlternative } from '../src/decode/rune.js';
import { ccanVectors, FIXED_AUTHENTICATOR, rune, runeFingerprint } from './support/runes.js';

// Parsing follows Core Lightning v26.06.8 (ccan/ccan/rune/coding.c and rune.c, ccan base64 with
// the URL-safe maps). Expected values come from the upstream vectors and from bytes built here.

function parsed(text: string) {
  const result = decodeRuneText(text);
  if (!result.ok) throw new Error(`expected a rune, got ${result.reason}`);
  return result.facts;
}

const alt = (field: string, condition: string, value: string): RuneAlternative =>
  ({ field, condition: condition as RuneAlternative['condition'], value });

describe('RUNE/upstream ccan vectors', () => {
  const vectors = ccanVectors();

  it('RUNE/upstream the vendored file holds the upstream row kinds', () => {
    const kinds = new Set(vectors.map(vector => vector.kind));
    for (const kind of ['VALID', 'MALFORMED', 'DERIVE', 'BAD DERIVATION', 'PASS', 'FAIL']) expect(kinds.has(kind), kind).toBe(true);
  });

  for (const { kind, fields } of vectors.filter(vector => vector.kind === 'VALID' || vector.kind === 'BAD DERIVATION')) {
    it(`RUNE/upstream ${kind} ${fields[1]} decodes to the upstream authenticator and restrictions`, () => {
      const [hash, restrictions] = [fields[2].slice(0, 64), fields[2].slice(65)];
      const bytes = decodeRuneBase64(fields[3])!;
      expect(bytes.subarray(0, 32).toString('hex')).toBe(hash);
      expect(bytes.subarray(32).toString('latin1')).toBe(restrictions);
      const facts = parsed(fields[3]);
      expect(facts.fingerprint).toBe(`fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`);
      // Upstream writes these vectors canonically.
      expect(facts.nonCanonical).toBe(false);
      if (kind === 'VALID') {
        expect(facts.uniqueId).toBe(fields[4] ?? null);
        expect(facts.version).toBe(fields[5] ?? null);
      }
    });
  }

  for (const { fields } of vectors.filter(vector => vector.kind === 'MALFORMED')) {
    it(`RUNE/upstream MALFORMED ${fields[1]} is refused`, () => {
      expect(decodeRuneText(fields[3]).ok).toBe(false);
    });
  }

  it('RUNE/upstream DERIVE rows parse, and the derived rune adds exactly the listed alternatives', () => {
    for (const { fields } of vectors.filter(vector => vector.kind === 'DERIVE')) {
      const base = parsed(fields[2]);
      const derived = parsed(fields[3]);
      const added: RuneAlternative[] = [];
      for (let at = 4; at + 2 < fields.length; at += 3) if (fields[at] !== '') added.push(alt(fields[at], fields[at + 1], fields[at + 2]));
      if (added.length) expect(derived.restrictions.at(-1), fields[1]).toEqual(added);
      expect(derived.restrictions.slice(0, base.restrictions.length), fields[1]).toEqual(base.restrictions);
    }
  });

  it('RUNE/upstream escaped delimiters stay part of the value (run-altern-escape.c)', () => {
    const facts = parsed(rune('desc=@tipjar\\|jb55@sendsats.lol'));
    expect(facts.restrictions).toEqual([[alt('desc', '=', '@tipjar|jb55@sendsats.lol')]]);
    expect(parsed(rune('f3~\\&\\|\\\\')).restrictions).toEqual([[alt('f3', '~', '&|\\')]]);
  });
});

describe('RUNE/base64 the URL-safe decoder accepts exactly what ccan accepts', () => {
  const bytes = Buffer.concat([FIXED_AUTHENTICATOR, Buffer.from('method=getinfo')]); // 46 bytes
  const padded = rune('method=getinfo');
  const unpadded = padded.replace(/=+$/, '');

  it('RUNE/base64 padded and unpadded forms decode to the same bytes and fingerprint', () => {
    expect(padded.endsWith('=')).toBe(true);
    expect(decodeRuneBase64(padded)).toEqual(bytes);
    expect(decodeRuneBase64(unpadded)).toEqual(bytes);
    expect(parsed(unpadded).fingerprint).toBe(parsed(padded).fingerprint);
    expect(parsed(padded).fingerprint).toBe(runeFingerprint('method=getinfo'));
    expect(parsed(padded).nonCanonical).toBe(false);
    expect(parsed(unpadded).nonCanonical).toBe(true);
  });

  it('RUNE/base64 extra trailing padding in the last group is dropped, as ccan does', () => {
    // 46 bytes: the last group has two characters; ccan strips every trailing '=' of that group.
    expect(decodeRuneBase64(`${unpadded}==`)).toEqual(bytes);
    expect(decodeRuneBase64(`${unpadded}=`)).toEqual(bytes);
  });

  it('RUNE/base64 refuses the standard alphabet, whitespace, inner padding and a one-character tail', () => {
    const at = (text: string, index: number, character: string) => `${text.slice(0, index)}${character}${text.slice(index + 1)}`;
    for (const bad of [at(padded, 8, '+'), at(padded, 8, '/'), `${padded.slice(0, 8)} ${padded.slice(8)}`, at(padded, 8, '='),
      `${unpadded.slice(0, unpadded.length - (unpadded.length % 4))}A`, `${padded}\n`, at(padded, 20, 'é'), 'A', 'AAAAA'])
      expect(decodeRuneBase64(bad), JSON.stringify(bad)).toBeNull();
  });

  it('RUNE/base64 ignores unused trailing bits, as ccan does (no canonical check)', () => {
    const text = unpadded.slice(0, -1) + String.fromCharCode(unpadded.charCodeAt(unpadded.length - 1) ^ 1);
    const decoded = decodeRuneBase64(text);
    expect(decoded?.length).toBe(bytes.length);
  });

  it('RUNE/base64 an empty value decodes to nothing; fewer than 32 bytes is too short', () => {
    expect(decodeRuneBase64('')).toEqual(Buffer.alloc(0));
    expect(decodeRuneText(Buffer.alloc(31).toString('base64url'))).toEqual({ ok: false, reason: 'too-short' });
  });

  it('RUNE/base64 a 32-byte rune with no restriction parses (no unique ID)', () => {
    const facts = parsed(rune(''));
    expect(facts).toMatchObject({ uniqueId: null, version: null, restrictions: [] });
  });
});

describe('RUNE/syntax restriction parsing', () => {
  it('RUNE/syntax every operator parses with its condition', () => {
    for (const condition of ['!', '=', '/', '^', '$', '~', '<', '>', '{', '}', '#'])
      expect(parsed(rune(`=1&f${condition}v`)).restrictions, condition).toEqual([[alt('f', condition, 'v')]]);
  });

  it('RUNE/syntax AND of OR alternatives keeps its structure', () => {
    const facts = parsed(rune('=3&method=pay|method=keysend&time<1800000000'));
    expect(facts.uniqueId).toBe('3');
    expect(facts.restrictions).toEqual([[alt('method', '=', 'pay'), alt('method', '=', 'keysend')], [alt('time', '<', '1800000000')]]);
  });

  it('RUNE/syntax `/` is "not equal", not a regular expression', () => {
    expect(parsed(rune('method/withdraw')).restrictions).toEqual([[alt('method', '/', 'withdraw')]]);
  });

  it('RUNE/syntax field names stop at punctuation other than underscore; spaces and high bytes belong to the name', () => {
    expect(parsed(rune('f_with_underscores=v1')).restrictions[0][0].field).toBe('f_with_underscores');
    expect(parsed(rune('a b=c')).restrictions[0][0].field).toBe('a b');
    const high = parsed(rune('caf\xe9=1', FIXED_AUTHENTICATOR, 'latin1'));
    expect(high.restrictions[0][0].field).toBe('caf\xe9');
  });

  it('RUNE/syntax refuses an invalid condition, an empty restriction, a dangling escape and a trailing OR', () => {
    for (const text of ['f1"11', 'f1&11', 'f1|11', 'f1', '&', 'f=1&&g=2', 'f=a\\', 'f=1|', 'f=1|g', '|f=1'])
      expect(decodeRuneText(rune(text)), text).toMatchObject({ ok: false, reason: 'restriction-syntax' });
  });

  it('RUNE/syntax a trailing AND is accepted, as Core Lightning accepts it, and marked non-canonical', () => {
    const facts = parsed(rune('=1&method=getinfo&'));
    expect(facts.restrictions).toEqual([[alt('method', '=', 'getinfo')]]);
    expect(facts.nonCanonical).toBe(true);
  });

  it('RUNE/syntax an unnecessary escape is accepted and marked non-canonical', () => {
    const facts = parsed(rune('method=get\\info'));
    expect(facts.restrictions[0][0].value).toBe('getinfo');
    expect(facts.nonCanonical).toBe(true);
  });

  it('RUNE/syntax a NUL byte in the restriction text is refused; one in the authenticator is not', () => {
    expect(decodeRuneText(rune('f=a\0b'))).toEqual({ ok: false, reason: 'nul-byte' });
    expect(decodeRuneText(rune('f=a', Buffer.alloc(32, 0))).ok).toBe(true);
  });
});

describe('RUNE/unique-id ID and version placement (rune_add_restr)', () => {
  it('RUNE/unique-id the first restriction with an empty field is the unique ID, kept as a string', () => {
    expect(parsed(rune('=0042&method=getinfo'))).toMatchObject({ uniqueId: '0042', version: null });
    expect(parsed(rune('=7-2'))).toMatchObject({ uniqueId: '7', version: '2' });
    expect(parsed(rune('=7-'))).toMatchObject({ uniqueId: '7', version: '' });
    expect(parsed(rune('=7-a-b'))).toMatchObject({ uniqueId: '7', version: 'a-b' });
    expect(parsed(rune('='))).toMatchObject({ uniqueId: '', version: null, restrictions: [] });
    expect(parsed(rune('=99999999999999999999999')).uniqueId).toBe('99999999999999999999999');
  });

  it('RUNE/unique-id the unique ID is separate from the id field, which names the peer', () => {
    const facts = parsed(rune('=5&id=02' + 'ab'.repeat(32)));
    expect(facts.uniqueId).toBe('5');
    expect(facts.restrictions).toEqual([[alt('id', '=', '02' + 'ab'.repeat(32))]]);
  });

  it('RUNE/unique-id refuses an ID that is not first, not alone, not "=", or repeated', () => {
    for (const text of ['method=getinfo&=1', '=1|f=2', 'f=2|=1', '!1', '/1', '^1', '$1', '~1', '<1', '>1', '{1', '}1', '#1',
      '=1-2&=3', '=1-2&=1-3'])
      expect(decodeRuneText(rune(text)), text).toMatchObject({ ok: false, reason: 'unique-id-placement' });
  });
});

describe('RUNE/limits parser bounds fail closed', () => {
  it('RUNE/limits a rune text longer than the limit is not parsed at all', () => {
    const text = rune(`=1&f=${'a'.repeat(RUNE_TEXT_LIMIT)}`);
    expect(text.length).toBeGreaterThan(RUNE_TEXT_LIMIT);
    expect(decodeRuneText(text)).toEqual({ ok: false, reason: 'exceeds-bounds' });
  });

  it('RUNE/limits more restrictions or alternatives than the limits are refused, never truncated', () => {
    const restrictions = Array.from({ length: RUNE_RESTRICTION_LIMIT + 1 }, (_, index) => `f=${index}`).join('&');
    expect(decodeRuneText(rune(restrictions))).toEqual({ ok: false, reason: 'exceeds-bounds' });
    const alternatives = Array.from({ length: RUNE_ALTERNATIVE_LIMIT + 1 }, () => 'f=1').join('|');
    expect(decodeRuneText(rune(alternatives))).toEqual({ ok: false, reason: 'exceeds-bounds' });
  });

  it('RUNE/limits the limits themselves are accepted', () => {
    const restrictions = Array.from({ length: RUNE_RESTRICTION_LIMIT }, () => 'f=1').join('&');
    expect(parsed(rune(restrictions)).restrictions).toHaveLength(RUNE_RESTRICTION_LIMIT);
    const alternatives = Array.from({ length: RUNE_ALTERNATIVE_LIMIT }, () => 'f=1').join('|');
    expect(parsed(rune(alternatives)).restrictions[0]).toHaveLength(RUNE_ALTERNATIVE_LIMIT);
  });
});
