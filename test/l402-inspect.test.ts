import { readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';
import { run as inspect } from '../src/commands/inspect.js';
import { run as verify } from '../src/commands/verify.js';
import { render, type OutputResult } from '../src/output/index.js';
import { encodings, fp, identifier, macaroon, sha256, token, tokenFile } from './helpers/l402-vectors.js';
import { expectDocumentValid } from './helpers/output-schema.js';
import { scratchDirectory } from './support/cp039-scratch.js';

// L402 inspect (docs/spec.md, Commands > 1. inspect, L402 input). Synthetic tokens only.
const networkCalls = vi.hoisted(() => [] as string[]);
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https') & { default: typeof import('node:https') }>();
  const blocked = () => { networkCalls.push('https'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked, default: { ...original.default, request: blocked, get: blocked } };
});

const repo = resolve();
const clock = () => new Date('2026-10-09T12:00:00Z');
const deps = (stdin: Readable = Readable.from([])) => ({ stdin: stdin as Readable & { isTTY?: boolean }, fs, clock });
type L402 = Extract<NonNullable<OutputResult['result']>, { kind: 'l402' }>;

async function withFile<T>(content: string | Buffer, work: (path: string) => Promise<T>, name = 'token.txt'): Promise<T> {
  const { dir, cleanup } = scratchDirectory('l402-');
  try {
    const path = join(dir, name);
    writeFileSync(path, content);
    return await work(path);
  } finally { cleanup(); }
}

/** No form of the preimage or the macaroon bytes appears in any rendering; JSON validates. */
function checkOutput(result: OutputResult, secrets: Buffer[]): void {
  for (const mode of ['text', 'json'] as const) {
    const out = render(result, mode);
    for (const secret of secrets) for (const form of encodings(secret))
      expect(out.includes(form), `${mode} output holds a credential encoding`).toBe(false);
    if (mode === 'json') expectDocumentValid(JSON.parse(out) as { command: string | null });
  }
}

it('L402-inspect/authorization reports identifier, services, capabilities, expiry, preimage match and service-access', async () => {
  const t = token(1);
  await withFile(`${t.header}\n`, async path => {
    const result = await inspect([path], deps());
    expect(result.error).toBeNull();
    expect(result.result).toEqual({
      kind: 'l402', fingerprint: t.fingerprint, macaroonFingerprint: t.macaroonFingerprint, macaroons: 1, form: 'authorization', scheme: 'L402',
      location: 'lsat', identifier: { version: 0, paymentHash: t.paymentHash.toString('hex'), tokenId: t.tokenId.toString('hex') },
      services: [{ name: 'weather', tier: '0' }],
      caveats: [
        { type: 'services', condition: 'services', value: 'weather:0' },
        { type: 'capabilities', condition: 'weather_capabilities', value: 'forecast,history', service: 'weather' },
        { type: 'valid-until', condition: 'weather_valid_until', value: '1893456000', service: 'weather',
          until: '2030-01-01T00:00:00Z', expired: false },
      ],
      preimage: 'matches', preimageSource: 'credential', status: 'live', expired: false,
      access: 'service-access', countedAs: 'READ', warnings: [],
    });
    checkOutput(result, [t.preimage, t.macaroon]);
    const text = render(result, 'text');
    expect(text).toMatch(/^kind\s+l402/m);
    expect(text).toMatch(/^payment hash\s+[0-9a-f]{64}$/m);
    expect(text).toMatch(/^counted as\s+READ by scan --fail-on$/m);
    expect(text).not.toMatch(/ADMIN|SPEND/);
    expect(networkCalls).toEqual([]);
  });
});

it('L402-inspect/forms: header line, LSAT scheme, pair, stdin and the --unsafe-arg literal give one fingerprint', async () => {
  const t = token(2);
  const forms = [`Authorization: L402 ${t.pair}`, `authorization:LSAT  ${t.pair}`, `l402\t${t.pair}`, t.pair];
  const prints = new Set<string>();
  for (const text of forms) {
    await withFile(text, async path => {
      const result = await inspect([path], deps());
      expect(result.error, text.slice(0, 20)).toBeNull();
      prints.add((result.result as L402).fingerprint);
      checkOutput(result, [t.preimage, t.macaroon]);
    });
  }
  const viaStdin = await inspect(['-'], deps(Readable.from([Buffer.from(t.header)])));
  prints.add((viaStdin.result as L402).fingerprint);
  const literal = await inspect([t.header, '--unsafe-arg'], deps());
  expect(literal.warnings).toEqual(['unsafe-arg']);
  prints.add((literal.result as L402).fingerprint);
  expect([...prints]).toEqual([t.fingerprint]);
  const lsat = await withFile(`LSAT ${t.pair}`, path => inspect([path], deps()));
  expect((lsat.result as L402).scheme).toBe('LSAT');
  const pair = await withFile(t.pair, path => inspect([path], deps()));
  expect((pair.result as L402)).toMatchObject({ form: 'pair', scheme: null });
});

it('L402-inspect/literal refusal: an L402 credential on the command line without --unsafe-arg exits 2 and is echoed nowhere', async () => {
  const t = token(3);
  for (const literal of [t.header, t.pair, `LSAT ${t.pair}`]) {
    const result = await inspect([literal], deps());
    expect(result.error).toMatchObject({ code: 2, step: null });
    checkOutput(result, [t.preimage, t.macaroon]);
  }
});

it('L402-inspect/bare macaroon: no preimage means unpaid and not counted; binary, hex and base64 agree', async () => {
  const t = token(4);
  const results: L402[] = [];
  for (const content of [t.macaroon, t.macaroon.toString('hex'), t.base64, t.macaroon.toString('base64url')]) {
    await withFile(content, async path => {
      const result = await inspect([path], deps());
      expect(result.error).toBeNull();
      checkOutput(result, [t.macaroon]);
      results.push(result.result as L402);
    });
  }
  for (const result of results) {
    expect(result).toMatchObject({ form: 'macaroon', preimage: 'absent', preimageSource: null, status: 'unpaid',
      countedAs: null, fingerprint: t.macaroonFingerprint, macaroonFingerprint: t.macaroonFingerprint });
  }
  const text = render({ command: 'inspect', ok: true, warnings: [], result: results[0], error: null }, 'text');
  expect(text).toMatch(/^preimage\s+absent; the macaroon alone grants nothing/m);
  expect(text).toMatch(/^counted as\s+not counted by scan --fail-on$/m);
});

it('L402-inspect/preimage caveat: a gRPC-style paid macaroon counts, and the caveat value is never shown', async () => {
  const t = token(5);
  const paid = macaroon(identifier(t.paymentHash, t.tokenId), ['services=lnd:0', `preimage=${t.preimage.toString('hex')}`]);
  await withFile(paid.toString('hex'), async path => {
    const result = await inspect([path], deps());
    expect(result.result).toMatchObject({ form: 'macaroon', preimage: 'matches', preimageSource: 'caveat', status: 'live',
      countedAs: 'READ', caveats: [{ type: 'services' }, { type: 'preimage', condition: 'preimage', value: null }] });
    checkOutput(result, [t.preimage, paid]);
    expect(render(result, 'text')).toMatch(/preimage=\(not shown\)/);
  });
});

it('L402-inspect/mismatch: a preimage that does not hash to the payment hash is reported and not counted', async () => {
  const t = token(6);
  const wrong = sha256(Buffer.from('another preimage'));
  await withFile(`L402 ${t.base64}:${wrong.toString('hex')}`, async path => {
    const result = await inspect([path], deps());
    expect(result.result).toMatchObject({ preimage: 'mismatch', status: 'preimage-mismatch', countedAs: null,
      fingerprint: fp(t.macaroon, wrong) });
    checkOutput(result, [wrong, t.macaroon]);
  });
});

it('L402-inspect/expiry uses the injected clock at the boundary (now = valid_until is expired) and keeps counting', async () => {
  const t = token(7, ['services=a:0,b:1', 'a_valid_until=1791547200', 'b_valid_until=1791547199']);
  const at = (iso: string) => ({ ...deps(), clock: () => new Date(iso) });
  await withFile(t.header, async path => {
    const before = await inspect([path], at('2026-10-09T11:59:59.999Z'));
    expect(before.result).toMatchObject({ status: 'live', expired: false });
    // 1791547200 is 2026-10-09T12:00:00Z: service b expired one second earlier, a expires now.
    const boundary = await inspect([path], at('2026-10-09T12:00:00.000Z'));
    expect(boundary.result).toMatchObject({ status: 'expired', expired: true, countedAs: 'READ',
      caveats: [{ type: 'services' }, { service: 'a', expired: true }, { service: 'b', expired: true }] });
    const onlyB = await inspect([path], at('2026-10-09T11:59:59.500Z'));
    expect(onlyB.result).toMatchObject({ status: 'live', expired: false,
      caveats: [{ type: 'services' }, { service: 'a', expired: false }, { service: 'b', expired: true }] });
  });
});

it('L402-inspect/caveat kinds: constraints, unknown, third-party, last services caveat, bad values', async () => {
  const t = token(8, ['services=x:0', 'services=x:0,y:2', 'max_calls=10', 'no equals sign', { thirdParty: 'https://auth.example' },
    'x_valid_until=soon', 'services=bad']);
  await withFile(t.header, async path => {
    const result = await inspect([path], deps());
    const facts = result.result as L402;
    expect(facts.caveats.map(caveat => caveat.type)).toEqual(['services', 'services', 'constraint', 'unknown', 'third-party',
      'valid-until', 'services']);
    expect(facts.caveats[2]).toEqual({ type: 'constraint', condition: 'max_calls', value: '10' });
    expect(facts.caveats[3]).toEqual({ type: 'unknown', condition: null, value: 'no equals sign' });
    expect(facts.caveats[4]).toEqual({ type: 'third-party', condition: null, value: 'https://auth.example' });
    expect(facts.services).toEqual([]);
    expect(facts.warnings).toEqual(['l402-bad-services', 'l402-bad-valid-until']);
    checkOutput(result, [t.preimage, t.macaroon]);
  });
  const good = token(9, ['services=x:0', 'services=x:0,y:2']);
  const result = await inspect([good.header, '--unsafe-arg'], deps());
  expect((result.result as L402).services).toEqual([{ name: 'x', tier: '0' }, { name: 'y', tier: '2' }]);
});

it('L402-inspect/withheld: a caveat or location that carries the preimage is not reported', async () => {
  const t = token(10);
  const hex = t.preimage.toString('hex');
  const mac = macaroon(identifier(t.paymentHash, t.tokenId), [`note=${hex.toUpperCase()}`,
    `copy=${t.preimage.toString('base64url')}`, 'services=s:0'], `loc-${t.preimage.toString('base64').slice(0, 43)}`);
  await withFile(`L402 ${mac.toString('base64')}:${hex}`, async path => {
    const result = await inspect([path], deps());
    expect(result.result).toMatchObject({ location: null, caveats: [{ type: 'withheld', condition: null, value: null },
      { type: 'withheld', condition: null, value: null }, { type: 'services' }], warnings: ['l402-caveat-withheld'] });
    checkOutput(result, [t.preimage, mac]);
  });
});

it('L402-inspect/token store files: paid, pending (zero preimage) and legacy names', async () => {
  const t = token(11);
  for (const name of ['l402.token', 'lsat.token', 'l402.token.pending']) {
    const pending = name.endsWith('.pending');
    await withFile(tokenFile(t, pending), async path => {
      const result = await inspect([path], deps());
      expect(result.error, name).toBeNull();
      expect(result.result).toMatchObject(pending
        ? { form: 'token-file', preimage: 'absent', status: 'unpaid', countedAs: null, fingerprint: t.macaroonFingerprint }
        : { form: 'token-file', preimage: 'matches', status: 'live', countedAs: 'READ', fingerprint: t.fingerprint });
      checkOutput(result, [t.preimage, t.macaroon]);
    }, name);
  }
  const other = token(12);
  const mixed = tokenFile(t);
  other.paymentHash.copy(mixed, 4 + t.macaroon.length);
  const result = await withFile(Buffer.concat([mixed, Buffer.from('extra')]), path => inspect([path], deps()));
  expect((result.result as L402).warnings).toEqual(['l402-token-hash-differs', 'trailing-bytes']);
});

it('L402-inspect/unrecognised identifier: the macaroon is reported, its preimage cannot be checked and still counts', async () => {
  const t = token(13);
  const mac = macaroon(Buffer.from('opaque server identifier'), ['services=s:0'], 'other');
  await withFile(`L402 ${mac.toString('base64')}:${t.preimage.toString('hex')}`, async path => {
    const result = await inspect([path], deps());
    expect(result.result).toMatchObject({ identifier: null, preimage: 'unverifiable', status: 'live', countedAs: 'READ',
      warnings: ['l402-identifier-unrecognized'] });
    checkOutput(result, [t.preimage, mac]);
    expect(render(result, 'text')).toMatch(/^identifier\s+not an L402 version 0 identifier$/m);
  });
});

it('L402-inspect/an Authorization value carrying an LND macaroon is inspected as that LND macaroon', async () => {
  const lnd = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
  const preimage = sha256(Buffer.from('x')).toString('hex');
  await withFile(`L402 ${lnd.toString('base64')}:${preimage}`, async path => {
    const result = await inspect([path], deps());
    expect(result.result).toMatchObject({ grade: 'READ', location: 'lnd' });
    expect((result.result as { kind?: string }).kind).toBeUndefined();
  });
});

it('L402-inspect/malformed input exits 3 at its stage and echoes nothing', async () => {
  const t = token(14);
  const cases: [string | Buffer, string][] = [
    [`L402 ${Array(17).fill(t.base64).join(',')}:${t.preimage.toString('hex')}`, 'l402-form'],
    [`L402 ${t.base64},:${t.preimage.toString('hex')}`, 'l402-form'],
    [`WWW-Authenticate: L402 macaroon="%%%", invoice="lnbc1"`, 'l402-form'],
    [`L402 invoice="lnbc1"`, 'l402-form'],
    [`L402 ${t.base64}`, 'l402-form'],
    [`L402 ${t.base64.slice(0, -2)}%%:${t.preimage.toString('hex')}`, 'l402-form'],
    [`L402 ${t.base64}:${t.preimage.toString('hex').slice(2)}`, 'l402-preimage'],
    [`L402 ${t.base64}:${t.preimage.toString('hex')}00`, 'l402-preimage'],
    [`L402 ${t.base64} x:${t.preimage.toString('hex')}`, 'l402-form'],
    [`L402 ${Buffer.from('not a macaroon at all, just text').toString('base64')}:${t.preimage.toString('hex')}`, 'v2-header'],
    [`L402 ${t.macaroon.subarray(0, 60).toString('base64')}:${t.preimage.toString('hex')}`, 'packet'],
    // Without Aperture's token store framing, a zero first byte is no token file: read as before.
    [tokenFile(t).subarray(0, 40), 'input-form'],
    [Buffer.concat([Buffer.from([0, 1, 0, 1]), Buffer.alloc(200, 2)]), 'input-form'],
    // With the framing, a broken macaroon fails at its decoding stage.
    [Buffer.concat([Buffer.from([0, 0, 0, 60]), t.macaroon.subarray(0, 60), Buffer.alloc(88)]), 'packet'],
  ];
  for (const [content, stage] of cases) {
    await withFile(content, async path => {
      const result = await inspect([path], deps());
      expect(result.error, stage).toMatchObject({ code: 3, step: stage });
      checkOutput(result, [t.preimage, t.macaroon]);
    });
  }
});

it('L402-inspect/verify refuses an L402 token as not an LND credential, before any network call', async () => {
  const t = token(15);
  const calls: string[] = [];
  const lnd = new Proxy({}, { get: (_target, name) => () => { calls.push(String(name)); throw new Error('LND called'); } });
  for (const content of [t.header, t.base64, tokenFile(t)]) {
    await withFile(content, async path => {
      const result = await verify([path, '--registry', join(path, '..', 'registry.json'), '--lnd-rest', '127.0.0.1:1',
        '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', resolve('test/vectors/default-admin.macaroon')],
      { lnd: lnd as never, fs, env: {}, clock });
      expect(result.error).toMatchObject({ code: 3, step: 'input-form' });
      expect(result.error?.message).toMatch(/L402/);
      checkOutput(result, [t.preimage, t.macaroon]);
    });
  }
  expect(calls).toEqual([]);
  expect(networkCalls).toEqual([]);
});

it('L402-inspect/several macaroons: the primary (first L402 identifier) is described, the fingerprint covers all of them', async () => {
  const t = token(16);
  const extra = macaroon(Buffer.from('discharge for a third-party caveat'), ['x=1'], 'auth.example');
  const hex = t.preimage.toString('hex');
  // The L402 macaroon comes second: it is still the primary one.
  await withFile(`L402 ${extra.toString('base64')},${t.base64}:${hex}`, async path => {
    const result = await inspect([path], deps());
    expect(result.result).toMatchObject({ macaroons: 2, macaroonFingerprint: t.macaroonFingerprint, location: 'lsat',
      preimage: 'matches', status: 'live', countedAs: 'READ', warnings: ['l402-several-macaroons'],
      fingerprint: fp(extra, t.macaroon, t.preimage) });
    checkOutput(result, [t.preimage, t.macaroon, extra]);
    expect(render(result, 'text')).toMatch(/^form\s+authorization \(L402 scheme\), 2 macaroons/m);
  });
  const sixteen = await inspect([`L402 ${Array(16).fill(t.base64).join(',')}:${hex}`, '--unsafe-arg'], deps());
  expect((sixteen.result as L402).macaroons).toBe(16);
});

it('L402-inspect/challenges: WWW-Authenticate with macaroon= or token=, quoted or bare, invoice first or last, LSAT', async () => {
  const t = token(17);
  const forms = [
    `WWW-Authenticate: L402 macaroon="${t.base64}", invoice="lnbcrt10n1synthetic"`,
    `L402 invoice="lnbcrt10n1synthetic", macaroon="${t.base64}"`,
    `LSAT macaroon=${t.base64}, invoice=lnbcrt10n1synthetic`,
    `L402 token="${t.base64}", invoice="lnbcrt10n1synthetic"`,
    `www-authenticate:LSAT macaroon="${t.base64}", invoice="lnbcrt10n1synthetic", L402 macaroon="${t.base64}", invoice="lnbcrt10n1synthetic"`,
  ];
  for (const text of forms) {
    await withFile(text, async path => {
      const result = await inspect([path], deps());
      expect(result.error, text.slice(0, 30)).toBeNull();
      expect(result.result).toMatchObject({ form: 'challenge', preimage: 'absent', status: 'unpaid', countedAs: null,
        fingerprint: t.macaroonFingerprint, macaroons: 1 });
      expect((result.result as L402).scheme).toBe(/^(?:www-authenticate:)?LSAT/i.test(text) ? 'LSAT' : 'L402');
      checkOutput(result, [t.macaroon]);
    });
  }
});

it('L402-inspect/the output choke point redacts L402 forms in any rendered string', () => {
  const t = token(18);
  const texts = [t.header, `LSAT ${t.pair}`, t.pair, t.macaroon.toString('hex'), t.base64, t.macaroon.toString('base64url'),
    `prefix ${t.header} suffix`];
  for (const text of texts) {
    const result = { command: null, ok: true, warnings: [], result: { text }, error: null } as OutputResult;
    for (const mode of ['text', 'json'] as const) {
      const out = render(result, mode);
      for (const secret of [t.preimage, t.macaroon]) for (const form of encodings(secret))
        expect(out.includes(form), `${mode} ${text.slice(0, 12)}`).toBe(false);
      expect(out).toContain('[redacted]');
    }
  }
});

it('L402-inspect/bounds: hostile input never exits 8, stays within the read limit and decodes in linear time', async () => {
  const t = token(19);
  const hex = t.preimage.toString('hex');
  const manyCaveats = macaroon(identifier(t.paymentHash, t.tokenId), Array.from({ length: 5000 }, (_, i) => `c${i}=v`));
  const cases: (string | Buffer)[] = [
    `L402 ${'A'.repeat(1_048_000)}:${hex}`,
    `L402 ${'A'.repeat(100)},`.repeat(5000),
    `L402 macaroon="${'A'.repeat(500_000)}"`,
    `${'A'.repeat(1_048_000)}:${hex}`,
    `L402 ${manyCaveats.toString('base64')}:${hex}`,
    Buffer.alloc(1_048_577, 0x41),
  ];
  // Deterministic pseudo-random corruption of a valid header (no randomness between runs).
  let seed = 7;
  const next = () => (seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648);
  for (let i = 0; i < 200; i++) {
    const bytes = Buffer.from(t.header);
    for (let flips = 0; flips < 1 + (i % 5); flips++) bytes[5 + (next() % (bytes.length - 5))] = 32 + (next() % 95);
    cases.push(bytes.toString('latin1').slice(0, next() % bytes.length + 1));
  }
  for (const content of cases) {
    await withFile(content, async path => {
      const result = await inspect([path], deps());
      expect(result.error?.code ?? 0, 'never an internal error').not.toBe(8);
      if (result.error) expect([3]).toContain(result.error.code);
      checkOutput(result, [t.preimage, t.macaroon]);
    });
  }
  const bounded = await withFile(`L402 ${manyCaveats.toString('base64')}:${hex}`, path => inspect([path], deps()));
  expect((bounded.result as L402).caveats).toHaveLength(4096);
  expect((bounded.result as L402).warnings).toContain('caveats-exceed-bounds');
  // Four times the caveats take at most about four times as long (headroom for noise).
  const timed = async (count: number) => {
    const mac = macaroon(identifier(t.paymentHash, t.tokenId), Array.from({ length: count }, (_, i) => `c${i}=v`));
    return withFile(`L402 ${mac.toString('base64')}:${hex}`, async path => {
      const started = performance.now();
      await inspect([path], deps());
      return performance.now() - started;
    });
  };
  await timed(500);
  const small = await timed(1000);
  const large = await timed(4000);
  expect(large).toBeLessThan(8 * Math.max(small, 25));
}, 120_000);

it('L402-inspect/schemas: inspect and scan share the L402 definitions and reject documents that break the contract', async () => {
  const Ajv2020 = (await import('ajv/dist/2020.js')).default as unknown as typeof import('ajv/dist/2020.js').default;
  const schemaFile = (name: string) => JSON.parse(readFileSync(join(repo, 'schemas/output', `${name}.schema.json`), 'utf8'));
  const inspectSchema = schemaFile('inspect');
  const scanSchema = schemaFile('scan');
  expect(scanSchema.$defs.l402Facts).toEqual(inspectSchema.$defs.l402Facts);
  expect(scanSchema.$defs.l402Caveat).toEqual(inspectSchema.$defs.l402Caveat);
  const validate = new Ajv2020({ strict: false }).compile(inspectSchema);
  const t = token(20);
  const good = await withFile(t.header, path => inspect([path], deps()));
  const document = JSON.parse(render(good, 'json')) as { result: Record<string, unknown> };
  expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
  const broken: Record<string, unknown>[] = [
    { preimageHex: t.preimage.toString('hex') },
    { grade: 'ADMIN' },
    { access: 'node-control' },
    { countedAs: null },
    { status: 'unpaid' },
    { preimage: 'absent' },
    { identifier: null },
    { macaroons: 0 },
    { form: 'header' },
    { scheme: null },
    { caveats: [{ type: 'preimage', condition: 'preimage', value: t.preimage.toString('hex') }] },
    { caveats: [{ type: 'valid-until', condition: 'x_valid_until', value: '1' }] },
    { caveats: [{ type: 'services', condition: 'services', value: 'a:0', expired: true }] },
    { warnings: ['made-up'] },
  ];
  for (const change of broken) {
    const changed = { ...document, result: { ...document.result, ...change } };
    expect(validate(changed), JSON.stringify(Object.keys(change))).toBe(false);
  }
});
