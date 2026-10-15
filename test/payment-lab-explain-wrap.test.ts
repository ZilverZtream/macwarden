import { expect, it } from 'vitest';

// Audit 1.3.2: wrap() escaped a continuation line's leading '::' only after wrapping, which made a
// full line 3 characters longer than MAX_LINE; renderText then cut the line's last characters.
// The module is loaded by a computed specifier, as test/helpers/payment-lab-modules.ts loads the lab.
type Format = { wrap(first: string, text: string, indent: string): string[]; MAX_LINE: number };
const relative = 'explain/format.ts';
const { wrap, MAX_LINE } = await import(/* @vite-ignore */ `../examples/payment-lab/src/${relative}`) as Format;

it('LAB-EXPLAIN/wrap a continuation line that starts with :: is escaped and still fits, losing nothing', () => {
  const cut = 'a'.repeat(MAX_LINE - 'x: '.length) + '::' + 'b'.repeat(200);
  const packed = `word ::${'c'.repeat(116)}`;
  for (const [first, text] of [['x: ', cut], ['k: ', packed]] as const) {
    const lines = wrap(first, text, '  ');
    for (const line of lines) {
      expect(line.length, line.slice(0, 12)).toBeLessThanOrEqual(MAX_LINE);
      expect(line, line.slice(0, 12)).not.toMatch(/^ *::/);
    }
    // Every character of the text is kept: undo the indent and the escape, and the words come back.
    const rebuilt = lines.map((line, index) => index === 0 ? line.slice(first.length) : line.slice(2))
      .map(line => line.replace(/^\\x3a:/, '::'));
    expect(rebuilt.join('').replace(/ /g, '')).toBe(text.replace(/ /g, ''));
  }
});
