import { revealSecret } from './helpers/secret-bytes.js';
import { render } from './helpers/render-adversarial.js';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { findLeaks } from "./helpers/leak-check.js";

type Facts = { location: string | null; rootKeyId: bigint; permissions: string[];
  caveats: { type: string; value: string; expired?: boolean }[]; fingerprint: string };
type Boundary = { decodeMacaroon(mac: Secret): Facts;
  addFirstPartyCaveat(mac: Secret, condition: string): Secret;
  timeBeforeCondition(expires: string, clock: () => Date): string };
const repo = resolve();

const boundary = async (): Promise<Boundary> => import('../src/decode/index.js') as Promise<Boundary>;
const sourcePath = join(repo, 'test/vectors/time-before.macaroon');
const oracle = JSON.parse(readFileSync(join(repo, 'test/vectors/time-before.printmacaroon.json'), 'utf8')) as {
  location: string; root_key_id: string; permissions: string[]; caveats: string[] };
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; canonicalLength: number; expectedGrade: string }[] };
const sourceEntry = manifest.vectors.find(item => item.name === 'time-before');
if (!sourceEntry) throw new Error('Missing committed time-before reference vector');
const fingerprint = (bytes: Buffer) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
const original = () => new Secret(readFileSync(sourcePath));
const fixedClock = () => new Date('2026-10-02T09:00:00.789Z');

it('CP-021/B1 appends a first-party caveat while preserving the original Secret and facts', async () => {
  const api = await boundary();
  const mac = original();
  const beforeBytes = Buffer.from(revealSecret(mac));
  const before = api.decodeMacaroon(mac);
  const caveat = 'time-before 2026-12-31T09:00:00Z';
  const attenuated = api.addFirstPartyCaveat(mac, caveat);
  expect(attenuated).toBeInstanceOf(Secret);
  expect(attenuated).not.toBe(mac);
  const afterBytes = Buffer.from(revealSecret(attenuated));
  const after = api.decodeMacaroon(attenuated);
  expect(Buffer.from(revealSecret(mac)).equals(beforeBytes)).toBe(true);
  expect(api.decodeMacaroon(mac)).toEqual(before);
  expect(before.fingerprint).toBe(sourceEntry.fingerprint);
  expect(fingerprint(beforeBytes.subarray(0, sourceEntry.canonicalLength))).toBe(sourceEntry.fingerprint);
  expect(after.rootKeyId.toString()).toBe(oracle.root_key_id);
  expect(after.location).toBe(oracle.location);
  expect(after.permissions).toEqual(oracle.permissions);
  expect(before.caveats.map(item => `${item.type} ${item.value}`)).toEqual(oracle.caveats);
  expect(after.caveats.slice(0, -1)).toEqual(before.caveats);
  expect(after.caveats.at(-1)).toMatchObject({ type: 'time-before', value: '2026-12-31T09:00:00Z' });
  expect(after.caveats).toHaveLength(oracle.caveats.length + 1);
  expect(after.fingerprint).toBe(fingerprint(afterBytes));
  expect(after.fingerprint).not.toBe(before.fingerprint);
});

for (const [input, expected] of [
  ['1m', '2026-10-02T09:01:00Z'],
  ['24h', '2026-10-03T09:00:00Z'],
  ['99999d', '2300-07-17T09:00:00Z'],
] as const) {
  it(`CP-021/B2 accepts expiry ${input} within the specified range`, async () => {
    expect((await boundary()).timeBeforeCondition(input, fixedClock)).toBe(`time-before ${expected}`);
  });
}

for (const input of ['0m', '100000d', '5w', '1.5h', 'h', ''] as const) {
  it(`CP-021/B2 rejects invalid expiry ${input || '(empty)'} with a usage error`, async () => {
    const api = await boundary();
    const { UsageError } = await import('../src/errors.js');
    let thrown: unknown;
    try { api.timeBeforeCondition(input, fixedClock); } catch (error) { thrown = error; }
    expect(thrown).toBeInstanceOf(UsageError);
    expect(thrown).toMatchObject({ name: 'UsageError', code: 2 });
  });
}

it('CP-021/B3 derives UTC seconds from an injected fractional clock in different time zones', async () => {
  const api = await boundary();
  const previous = process.env.TZ;
  try {
    for (const zone of ['UTC', 'America/Los_Angeles', 'Pacific/Auckland']) {
      process.env.TZ = zone;
      expect(api.timeBeforeCondition('90d', fixedClock), zone)
        .toBe('time-before 2026-12-31T09:00:00Z');
    }
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
});

it('CP-021/B4 text and JSON reveal no original or attenuated credential on success or invalid expiry', async () => {
  const api = await boundary();
  const output = await import('../src/output/index.js');
  const mac = original();
  const attenuated = api.addFirstPartyCaveat(mac, 'time-before 2026-12-31T09:00:00Z');
  const tmp = resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp'));
  const sentinelDir = resolve(process.env.MACWARDEN_SENTINEL_DIR || join(tmp, 'sentinels'));
  mkdirSync(sentinelDir, { recursive: true });
  writeFileSync(join(sentinelDir, 'cp021-original.macaroon'), Buffer.from(revealSecret(mac)));
  writeFileSync(join(sentinelDir, 'cp021-attenuated.macaroon'), Buffer.from(revealSecret(attenuated)));
  const options = { sentinels: join(repo, 'test/sentinels.json'), sentinelDir, root: repo };
  const value = api.decodeMacaroon(attenuated);
  const success = { schema: 1 as const, command: 'bake', ok: true, warnings: [],
    result: { nodePubkey: '02' + 'ab'.repeat(32), label: 'expiry-check',
      rootKeyId: oracle.root_key_id, permissions: oracle.permissions, grade: sourceEntry.expectedGrade,
      fingerprint: value.fingerprint, caveats: value.caveats,
      outPath: join(tmp, 'attenuated.macaroon'), createdAt: fixedClock().toISOString(),
      verified: true, status: 'active', revokedAt: null, revokeEvidence: null,
      replaces: null, replacedBy: null }, error: null };
  let failure: unknown;
  try { api.timeBeforeCondition(Buffer.from(revealSecret(mac)).toString('hex'), fixedClock); }
  catch (error) { failure = error; }
  const { UsageError } = await import('../src/errors.js');
  expect(failure instanceof UsageError).toBe(true);
  expect((failure as { code?: number })?.code).toBe(2);
  const message = (failure as Error).message;
  const failed = { schema: 1 as const, command: 'bake', ok: false, warnings: [], result: null,
    error: { code: 2, step: null, message } };
  for (const rendered of [render(success, 'text'), render(success, 'json'),
    render(failed, 'text'), render(failed, 'json'), output.error('expires', message)]) {
    expect(findLeaks({ ...options, commandOutput: rendered }), 'credential encoding in rendered output').toBeNull();
  }
  expect(JSON.parse(render(success, 'json')).result.fingerprint).toBe(value.fingerprint);
  expect(JSON.parse(render(failed, 'json')).error.code).toBe(2);
});
