import { render } from './helpers/render-adversarial.js';
import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();
const sentinel = () => readFileSync(join(repo, 'test', 'sentinels', 'sentinel.macaroon'));
const noLeak = (text: string, bytes: Buffer): void => {
  const b64 = bytes.toString('base64');
  const forms = [bytes.toString('utf8'), bytes.toString('latin1'), bytes.toString('hex'),
    bytes.toString('hex').toUpperCase(), b64, b64.replace(/=+$/, ''),
    b64.replace(/\+/g, '-').replace(/\//g, '_'), bytes.toString('base64url')];
  for (const form of forms) expect(text.includes(form), 'credential encoding leaked').toBe(false);
};

it('CP-003/B5 scan patterns retain the specified sources, flags and boundary', async () => {
  const patterns = await import('../src/scan/patterns.js');
  const expected: [RegExp | undefined, string, boolean][] = [
    [patterns.macaroonHex, '0201036c6e6402[0-9a-f]{40,}', true],
    [patterns.macaroonBase64, 'AgEDbG5kA[A-Za-z0-9+\\/_-]{40,}={0,2}', false],
    [patterns.lndconnect, 'lndconnect:\\/\\/[^\\s"\'<>]+', true],
    [patterns.nwc, '(?:nostr\\+walletconnect|nostrwalletconnect):(?:\\/\\/)?[0-9a-f]{64}\\/?\\?[^\\s"\'<>]*?secret=[0-9a-f]{64}(?:[^0-9a-f]|$)', true],
  ];
  for (const [actual, source, insensitive] of expected) {
    expect(actual).toBeInstanceOf(RegExp);
    expect(actual?.source).toBe(source);
    expect(actual?.flags.includes('i')).toBe(insensitive);
  }
  expect(patterns.macaroonHex.test('0201036c6e6402' + 'a'.repeat(39))).toBe(false);
  expect(patterns.macaroonHex.test('0201036c6e6402' + 'a'.repeat(40))).toBe(true);
});

it('CP-003/B6 output redacts every credential form and preserves ordinary text', async () => {
  const output = await import('../src/output/index.js');
  const bytes = sentinel();
  const nwcSecret = Buffer.alloc(32, 0x5a);
  const nwc = `nostr+walletconnect://${'b'.repeat(64)}?relay=wss://r&secret=${nwcSecret.toString('hex')}`;
  const messages = [bytes.toString('hex'), bytes.toString('hex').toUpperCase(),
    bytes.toString('base64'), bytes.toString('base64url'),
    `lndconnect://h:1?macaroon=${bytes.toString('base64url')}`, nwc];
  const envelope = (message: string) => ({ schema: 1 as const, command: 'inspect',
    ok: false, warnings: [], result: null, error: {code:3,step:'input-form',message} });
  for (const message of messages) {
    for (const rendered of [output.error('input-form', message),
      render(envelope(message), 'text')]) {
      expect(rendered.includes('[redacted]'), 'output lacks redaction').toBe(true);
      noLeak(rendered, bytes);
      noLeak(rendered, nwcSecret);
      expect(rendered.includes(nwcSecret.toString('hex')), 'NWC secret leaked').toBe(false);
    }
    const json = render(envelope(message), 'json');
    expect(json.includes('[redacted]'), 'JSON output lacks redaction').toBe(true);
    noLeak(json, bytes);
    noLeak(json, nwcSecret);
    let parsed: { error?: { message?: string } } | null = null;
    try { parsed = JSON.parse(json) as { error?: { message?: string } }; } catch { /* assertion below */ }
    expect(parsed !== null, 'JSON output must remain one parseable document').toBe(true);
    expect(parsed?.error?.message).toBe('[redacted]');
  }
  for (const suffix of [')', '!']) {
    const json = render(envelope(nwc + suffix), 'json');
    noLeak(json, nwcSecret);
    let parsed: { error?: { message?: string } } | null = null;
    try { parsed = JSON.parse(json) as { error?: { message?: string } }; } catch { /* assertion below */ }
    expect(parsed !== null, 'NWC delimiter must not break JSON syntax').toBe(true);
    expect(parsed?.error?.message).toBe(`[redacted]${suffix}`);
  }
  const ordinary = 'ordinary input with café';
  expect(render(envelope(ordinary), 'text')).toContain(ordinary);
  expect(output.error('input-form', ordinary)).toContain(ordinary);
  const ordinaryJson = render(envelope(ordinary), 'json');
  expect(JSON.parse(ordinaryJson)).toEqual(envelope(ordinary));
});

it('CP-003/B6 JSON envelopes preserve syntax and safe content around redacted strings', async () => {
  await import('../src/output/index.js');
  const bytes = sentinel();
  const nwcSecret = Buffer.alloc(32, 0x5a);
  const nwc = `nostr+walletconnect://${'b'.repeat(64)}?relay=wss://r&secret=${nwcSecret.toString('hex')}`;
  const cases: [string, string, string][] = [
    ['macaroon hex', bytes.toString('hex'), '"\\tail\x1b\x9b'],
    ['macaroon hex upper case', bytes.toString('hex').toUpperCase(), '"\\tail\x1b\x9b'],
    ['macaroon base64', bytes.toString('base64'), '"\\tail\x1b\x9b'],
    ['macaroon base64url', bytes.toString('base64url'), '"\\tail\x1b\x9b'],
    ['lndconnect', `lndconnect://h:1?macaroon=${bytes.toString('base64url')}`, '"\\tail\x1b\x9b'],
    ['nwc quote boundary', nwc, '"\\tail\x1b\x9b'],
    ['nwc closing parenthesis boundary', nwc, ') tail'],
    ['nwc punctuation boundary', nwc, '! tail'],
  ];

  for (const [label, credential, suffix] of cases) {
    const message = `safe prefix ${credential}${suffix} safe end`;
    const safeMessage = `safe prefix [redacted]${suffix} safe end`;
    const ordinary = 'ordinary caf\u00e9 \\ path';
    const result = { schema: 1 as const, command: 'inspect', ok: true, warnings: [],
      result: { detail: { message }, entries: [ordinary, { message }], [message]: ordinary },
      error: null };
    const safeResult = { ...result, result: { detail: { message: safeMessage },
      entries: [ordinary, { message: safeMessage }], [safeMessage]: ordinary } };
    const failure = { schema: 1 as const, command: 'inspect', ok: false, warnings: [],
      result: null, error: { code: 3, step: 'input-form', message } };
    const safeFailure = { ...failure,
      error: { code: 3, step: 'input-form', message: safeMessage } };

    for (const [kind, input, expected] of [
      ['result', result, safeResult], ['error', failure, safeFailure],
    ] as const) {
      const json = render(input, 'json');
      noLeak(json, bytes);
      noLeak(json, nwcSecret);
      expect.soft(json.includes('[redacted]'), `${label} ${kind} must redact`).toBe(true);
      let parsed: unknown = null;
      try { parsed = JSON.parse(json) as unknown; } catch { /* assertion below */ }
      expect.soft(parsed !== null, `${label} ${kind} must be one valid JSON document`).toBe(true);
      if (parsed !== null) {
        expect.soft(JSON.stringify(parsed) === JSON.stringify(expected),
          `${label} ${kind} must preserve the envelope and safe string content`).toBe(true);
      }
    }
  }
});

it('CP-003/B7 text output escapes C0, DEL and C1 while retaining Unicode', async () => {
  await import('../src/output/index.js');
  const path = `before\x1b\x07\x7f\x9bé-after`;
  const rendered = render({ path }, 'text');
  for (const escaped of ['\\x1b', '\\x07', '\\x7f', '\\x9b']) expect(rendered).toContain(escaped);
  expect(rendered).toContain('é');
  for (const raw of ['\x1b', '\x07', '\x7f', '\x9b']) expect(rendered.includes(raw)).toBe(false);
});
