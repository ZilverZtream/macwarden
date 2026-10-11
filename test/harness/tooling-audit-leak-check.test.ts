import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from '../../scripts/leak-check.mjs';

const repo = resolve();
const sentinelList = join(repo, 'test/sentinels.json');
const mac = readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const chunks = (text: string, size: number) => text.match(new RegExp(`.{1,${size}}`, 'g'))!;
const leaked = (text: string) => findLeaks({ sentinels: sentinelList, root: repo, commandOutput: text });

// Each built from a changed copy too: one flipped signature bit must not be reported, so a hit
// comes from the registered credential and not from the shape of the encoding.
const encodings: Record<string, (bytes: Buffer) => string> = {
  // Audit TOOLING-03: second-layer encodings and split values.
  'base64 of the hex text': bytes => Buffer.from(bytes.toString('hex')).toString('base64'),
  'hex of the base64 text': bytes => Buffer.from(bytes.toString('base64')).toString('hex'),
  'base64 of the base64 text': bytes => Buffer.from(bytes.toString('base64')).toString('base64'),
  'JSON array of base64 pieces': bytes => JSON.stringify(chunks(bytes.toString('base64'), 20)),
  'concatenated string literals': bytes => chunks(bytes.toString('base64'), 30).map(piece => `"${piece}"`).join(' +\n  '),
  'timestamp-prefixed log lines': bytes => chunks(bytes.toString('base64'), 40)
    .map((piece, index) => `2026-10-11T00:00:0${index % 10}Z INFO ${piece}`).join('\n'),
  'base64 split by zero-width spaces': bytes => [...bytes.toString('base64')].join('​'),
  // Audit TOOLING-04: parts equivalent to the credential.
  'all but the version byte, hex': bytes => bytes.subarray(1).toString('hex'),
  'all but the version byte, base64': bytes => bytes.subarray(1).toString('base64'),
  'the signature alone, hex': bytes => bytes.subarray(-32).toString('hex'),
  'the signature alone, base64': bytes => bytes.subarray(-32).toString('base64'),
};

it.each(Object.entries(encodings))('TOOLING-03/04 the leak check finds %s', (_, encode) => {
  expect(mac[0], 'the registered sentinel is a v2 macaroon').toBe(2);
  expect(mac.subarray(-35, -32), 'its signature field ends it').toEqual(Buffer.from([0x00, 0x06, 0x20]));
  const hit = leaked(`output before\n${encode(mac)}\noutput after`);
  expect(hit, 'positive control').not.toBeNull();
  expect(JSON.stringify(hit)).not.toContain(mac.toString('hex'));
  const changed = Buffer.from(mac); changed[changed.length - 1] ^= 1;
  expect(leaked(`output before\n${encode(changed)}\noutput after`), 'changed signature is not reported').toBeNull();
});

it('TOOLING-03 ordinary quoted lists, log lines and prose stay clean', () => {
  expect(leaked(['["alpha", "beta", "gamma"]', '"one" + "two"',
    '2026-10-11T00:00:00Z INFO started', '2026-10-11T00:00:01Z INFO stopped',
    Buffer.from('ordinary text with no credential').toString('base64'),
    Buffer.from(Buffer.from('ordinary text').toString('hex')).toString('base64')].join('\n'))).toBeNull();
});

// The split views and second-layer checks are single passes: a large adversarial capture of
// quotes, separators and whitespace stays well within the existing per-check budget.
it('TOOLING-03 the added views stay linear on adversarial input', () => {
  const size = 400_000;
  const inputs = ['"' + ' '.repeat(size) + 'x', `"${'"'.repeat(size)}`, ('a ' + ' '.repeat(64)).repeat(size / 66),
    `"${' ,'.repeat(size / 2)}`, 'A'.repeat(size) + ' B'];
  for (const input of inputs) {
    const started = performance.now();
    expect(leaked(input)).toBeNull();
    expect(performance.now() - started, 'bounded time').toBeLessThan(10_000);
  }
}, 120_000);
