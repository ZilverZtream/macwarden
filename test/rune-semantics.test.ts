import { describe, expect, it } from 'vitest';
import { decodeRuneText, type RuneAlternative, type RuneFacts } from '../src/decode/rune.js';
import { alternativeHolds, runeInteger } from '../src/grade/rune.js';
import { ccanVectors } from './support/runes.js';

// Condition semantics follow ccan/ccan/rune/rune.c rune_alt_single in Core Lightning v26.06.8.
// The upstream PASS/FAIL rows test the preceding VALID rune with the given fields; upstream's
// test passes a field that strtol reads completely as an integer, and anything else as a string.

function fieldValue(fields: string[], name: string): string | bigint | null {
  let value: string | null = null;
  for (const item of fields.slice(1)) if (item.startsWith(`${name}=`)) value = item.slice(name.length + 1);
  if (value === null) return null;
  return /^[ \t\n\v\f\r]*[+-]?[0-9]+$/.test(value) ? BigInt(value.trim().replace(/^\+/, '')) : value;
}

function passes(facts: RuneFacts, fields: string[]): boolean {
  return facts.restrictions.every(restriction => restriction.some(alternative => alternativeHolds(alternative, fieldValue(fields, alternative.field))));
}

describe('RUNE/semantics upstream PASS and FAIL rows', () => {
  let current: RuneFacts | null = null;
  let label = '';
  const rows: { label: string; facts: RuneFacts; fields: string[]; expected: boolean }[] = [];
  for (const { kind, fields } of ccanVectors()) {
    if (kind === 'VALID') {
      const decoded = decodeRuneText(fields[3]);
      current = decoded.ok ? decoded.facts : null;
      label = fields[1];
    } else if ((kind === 'PASS' || kind === 'FAIL') && current) rows.push({ label, facts: current, fields, expected: kind === 'PASS' });
  }

  it('RUNE/semantics the vendored vectors hold PASS and FAIL rows for every condition', () => {
    expect(rows.length).toBeGreaterThan(60);
  });

  for (const [index, row] of rows.entries()) {
    it(`RUNE/semantics ${row.label} row ${index}: ${row.expected ? 'PASS' : 'FAIL'} ${row.fields.slice(1).join(',')}`, () => {
      expect(passes(row.facts, row.fields)).toBe(row.expected);
    });
  }
});

const alt = (field: string, condition: RuneAlternative['condition'], value: string): RuneAlternative => ({ field, condition, value });

describe('RUNE/semantics each operator', () => {
  it('RUNE/semantics ! passes only for a missing field; # always passes', () => {
    expect(alternativeHolds(alt('f', '!', ''), null)).toBe(true);
    expect(alternativeHolds(alt('f', '!', ''), 'x')).toBe(false);
    expect(alternativeHolds(alt('f', '!', ''), 0n)).toBe(false);
    for (const value of [null, 'x', 5n] as const) expect(alternativeHolds(alt('f', '#', 'anything'), value)).toBe(true);
  });

  it('RUNE/semantics = and / compare exactly; a missing field fails both', () => {
    expect(alternativeHolds(alt('f', '=', 'pay'), 'pay')).toBe(true);
    expect(alternativeHolds(alt('f', '=', 'pay'), 'payx')).toBe(false);
    expect(alternativeHolds(alt('f', '/', 'pay'), 'keysend')).toBe(true);
    expect(alternativeHolds(alt('f', '/', 'pay'), 'pay')).toBe(false);
    expect(alternativeHolds(alt('f', '/', 'pay'), null)).toBe(false);
    // An integer field compares as its decimal text.
    expect(alternativeHolds(alt('f', '=', '7'), 7n)).toBe(true);
    expect(alternativeHolds(alt('f', '=', '07'), 7n)).toBe(false);
  });

  it('RUNE/semantics ^ $ ~ are prefix, suffix and substring tests', () => {
    expect(alternativeHolds(alt('f', '^', 'list'), 'listfunds')).toBe(true);
    expect(alternativeHolds(alt('f', '^', 'list'), 'getlist')).toBe(false);
    expect(alternativeHolds(alt('f', '$', 'pay'), 'xpay')).toBe(true);
    expect(alternativeHolds(alt('f', '~', 'pay'), 'renepaystatus')).toBe(true);
    expect(alternativeHolds(alt('f', '~', 'pay'), 'getinfo')).toBe(false);
  });

  it('RUNE/semantics < and > need an integer field and a valid 64-bit integer', () => {
    expect(alternativeHolds(alt('f', '<', '10'), 9n)).toBe(true);
    expect(alternativeHolds(alt('f', '<', '10'), 10n)).toBe(false);
    expect(alternativeHolds(alt('f', '>', '-5'), -4n)).toBe(true);
    expect(alternativeHolds(alt('f', '<', '10'), '9')).toBe(false);
    expect(alternativeHolds(alt('f', '<', 'ten'), 9n)).toBe(false);
    expect(alternativeHolds(alt('f', '<', '9223372036854775808'), 9n)).toBe(false);
    expect(alternativeHolds(alt('f', '<', '9223372036854775807'), 9n)).toBe(true);
    expect(alternativeHolds(alt('f', '<', ' +10'), 9n)).toBe(true);
    expect(alternativeHolds(alt('f', '<', '10 '), 9n)).toBe(false);
  });

  it('RUNE/semantics { and } compare bytes lexically; an integer field compares as text', () => {
    expect(alternativeHolds(alt('f', '{', 'b'), 'a')).toBe(true);
    expect(alternativeHolds(alt('f', '{', 'ab'), 'a')).toBe(true);
    expect(alternativeHolds(alt('f', '{', 'a'), 'a')).toBe(false);
    expect(alternativeHolds(alt('f', '}', 'a'), 'ab')).toBe(true);
    expect(alternativeHolds(alt('f', '{', '11'), 2n)).toBe(false);
    expect(alternativeHolds(alt('f', '{', '\x80'), '\x7f')).toBe(true);
  });

  it('RUNE/semantics integers are read as strtol on a 64-bit long reads them', () => {
    expect(runeInteger('1800000000')).toBe(1_800_000_000n);
    expect(runeInteger('  -12')).toBe(-12n);
    expect(runeInteger('+3')).toBe(3n);
    for (const bad of ['', ' ', '+', '1.5', '0x10', '12a', '9223372036854775808', '-9223372036854775809'])
      expect(runeInteger(bad), bad).toBeNull();
    expect(runeInteger('-9223372036854775808')).toBe(-(2n ** 63n));
  });
});
