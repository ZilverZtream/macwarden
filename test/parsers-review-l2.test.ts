// Parser review 2026-10-08, LOW-2: output redaction and scan's secret collection still ran
// the published lazy `nwc` regex, which backtracks quadratically when the prefix repeats
// without a secret (1 MB took 5 to 6 s in collectNwcSecrets and 11.7 s in render). They now
// use the linear matcher scan detection already uses, with identical results.
import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { render } from '../src/output/index.js';
import { replaceNwc } from '../src/scan/nwc-match.js';
import { nwc } from '../src/scan/patterns.js';
import { collectNwcSecrets, redactDecoded, redactPath } from '../src/scan/redact.js';
import { LINEAR_4X, growth } from './helpers/growth.js';

const prefix = `nostr+walletconnect:${'a'.repeat(64)}?`;
const KIB = 1024;

// Cost is measured as growth, not against a fixed limit, so a slow runner cannot fail it and a
// fast one cannot hide a regression: four times the text must cost well under the sixteen times
// that quadratic backtracking needs.
it('PARSERS-L2/repeated NWC prefixes four times longer are redacted and collected at about four times the cost', async () => {
  // Before: at 1 MiB collectNwcSecrets took 5 to 6 s and render 11.7 s, growing with the
  // square of the text. The remaining cost is the other (linear) credential recognisers,
  // which run on the same text.
  const repeated = (size: number) => prefix.repeat(Math.ceil(size / prefix.length));
  const collect = (size: number) => {
    const text = repeated(size);
    return () => { const secrets = new Set<string>(); collectNwcSecrets(text, secrets); expect(secrets.size).toBe(0); };
  };
  const redact = (size: number) => { const text = repeated(size); return () => expect(redactPath(text)).toBe(text); };
  const json = (size: number) => {
    const text = repeated(size);
    return () => render({ schema: 1, command: 'inspect', ok: true, warnings: [], error: null,
      result: { caveat: text } } as never, 'json');
  };
  for (const [name, work, n] of [['collect', collect, 1024 * KIB], ['redact', redact, 64 * KIB], ['render', json, 64 * KIB]] as const) {
    const timing = await growth(work, n, 4, 5);
    console.log(`PARSERS-L2 ${name} ${n / KIB} KiB and ${4 * n / KIB} KiB: ${timing.summary}`);
    expect(timing.ratio, `${name}: ${timing.summary}`).toBeLessThan(LINEAR_4X);
  }
}, 120_000);

it('PARSERS-L2/a secret after many repeated prefixes is still found and redacted', () => {
  const secret = randomBytes(32).toString('hex');
  const text = `${prefix.repeat(5_000)}relay=wss://r.example&secret=${secret} tail`;
  const secrets = new Set<string>();
  collectNwcSecrets(text, secrets);
  expect([...secrets]).toEqual([secret]);
  expect(redactDecoded(text)).not.toContain(secret);
  expect(redactDecoded(text).endsWith('[redacted] tail')).toBe(true);
  const json = render({ schema: 1, command: 'inspect', ok: true, warnings: [], error: null, result: { caveat: text } } as never, 'json');
  expect(json).not.toContain(secret);
});

it('PARSERS-L2/replaceNwc equals a global replace with the published regex on random text', () => {
  const regex = new RegExp(nwc.source, `${nwc.flags}g`);
  const hex = 'a'.repeat(64);
  const pick = <T>(values: T[]) => values[random(values.length)];
  const middle = ['relay=wss://x', '&', 'secret=', 'secret=' + hex.slice(1), 'b', ' ', '"', '<', 'é', '?', 'Secret=' + hex];
  const piece = () => pick([
    () => pick(['nostr+walletconnect:', 'NOSTRWALLETCONNECT:', 'nostrwalletconnect://', 'nostr+walletconnect:']) + pick(['', '//']) + pick([hex, hex.slice(1), hex + 'g']) + pick(['', '/']) + pick(['?', '']),
    () => pick(middle),
    () => pick(['secret=', '&secret=', '?secret=']) + pick([hex, hex + 'b', hex + ' ', hex.slice(2)]),
  ])();
  let seed = 7;
  const random = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return (seed >>> 16) % n; };
  let replaced = 0;
  for (let i = 0; i < 20_000; i++) {
    const text = Array.from({ length: 1 + random(8) }, piece).join('');
    const replacer = (match: string) => `<${match.length}>`;
    const expected = text.replace(regex, replacer);
    expect(replaceNwc(text, replacer), JSON.stringify(text)).toBe(expected);
    if (expected !== text) replaced++;
  }
  expect(replaced).toBeGreaterThan(100);
});
