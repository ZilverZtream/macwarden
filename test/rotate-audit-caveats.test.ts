// Pre-1.4 audit: rotate rebakes the replacement from the old credential's permissions and
// re-applies only the time-before caveat S11 reproduces from the recorded `requested` duration.
// Every other caveat of the old credential (an IP lock, a third-party or unknown caveat, an
// expiry without a recorded duration) was dropped silently, so the replacement of an IP-locked
// credential was unlocked. Such a credential is now refused at S5 before any LND call; respond
// skips it with a note and inventory prints no rotate advice for it (1.3.1).
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { Secret } from '../src/secret.js';
import { decodeMacaroon } from '../src/decode/index.js';
import { run as respond } from '../src/commands/respond.js';
import { run as inventory } from '../src/commands/inventory.js';
import { render } from '../src/output/index.js';
import { render as renderEnvelope } from './helpers/render-adversarial.js';
import type { RespondResult } from '../src/command-result.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { register, wireFixture } from './helpers/cp026-revoke-support.mjs';
import { failure, invoke, oldId, save, scratch, unchanged } from './helpers/cp028-rotate-support.js';
import { declareStagedFiles, declareStaging, entry as onlineEntry, fixture as onlineFixture,
  oldId as onlineOldId, ownId as onlineOwnId } from './helpers/cp038-online.js';
import { isolateLeakSuite } from './helpers/leak-suite.js';

isolateLeakSuite('rotate-audit-caveats');
vi.setConfig({ testTimeout: 60_000 });

const expiry = { type: 'time-before', value: '2027-01-01T00:00:00Z', requested: '90d' };
const wayOut = ['macwarden bake', 'macwarden attenuate', 'macwarden revoke Alice'];

function varint(value: number): Buffer {
  const bytes: number[] = [];
  do { bytes.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
  return Buffer.from(bytes);
}
const packet = (kind: number, bytes: Buffer) => Buffer.concat([varint(kind), varint(bytes.length), bytes]);
/** The caveat-free wire fixture with first-party caveats appended (v2: header EOS, caveat sections, EOS, signature). */
function withCaveats(bytes: Buffer, conditions: string[]): Buffer {
  const signature = bytes.subarray(bytes.length - 34);
  const header = bytes.subarray(0, bytes.length - 34 - 1);
  return Buffer.concat([header, ...conditions.flatMap(condition => [packet(2, Buffer.from(condition)), Buffer.from([0])]),
    Buffer.from([0]), signature]);
}

const refused = [
  ['ipaddr', [{ type: 'ipaddr', value: '127.0.0.1' }, expiry]],
  ['iprange', [expiry, { type: 'iprange', value: '10.0.0.0/8' }]],
  ['third-party', [{ type: 'third-party', value: 'https://example.invalid' }]],
  ['unknown', [{ type: 'unknown', value: 'custom condition' }]],
  ['time-before', [{ type: 'time-before', value: '2027-01-01T00:00:00Z' }]],
] as const;
for (const [named, caveats] of refused) {
  it.each(['stage', '--dry-run'])(`ROTATE-CAVEATS/S5 an entry with a ${named} caveat is refused before any LND call (%s)`, async mode => scratch(async f => {
    f.old.caveats = caveats.map(caveat => ({ ...caveat })); save(f);
    const before = readFileSync(f.registry);
    const result = await invoke(f, mode === 'stage' ? [] : [mode]);
    failure(f, result, 3, 'S5');
    expect(result.error!.message).toContain(named);
    // The expiry S11 reproduces is not a reason: it is not named.
    if (named !== 'time-before') expect(result.error!.message).not.toContain('time-before');
    for (const text of wayOut) expect(result.error!.message).toContain(text);
    expect(f.calls).toEqual([]); expect(f.lnd.bakeMacaroon).not.toHaveBeenCalled();
    expect(existsSync(f.out)).toBe(false); unchanged(f, before);
    expect(renderEnvelope(result, 'text')).toContain(named);
  }));
}

it('ROTATE-CAVEATS/S5 a caveat only the old credential file carries counts: the decoded file decides', async () => scratch(async f => {
  const bytes = withCaveats(wireFixture('preset-invoice-only', oldId), ['iprange 10.0.0.0/8']);
  const facts = decodeMacaroon(new Secret(bytes));
  expect(facts.caveats).toEqual([{ type: 'iprange', value: '10.0.0.0/8' }]);
  expect(String(facts.rootKeyId)).toBe(oldId);
  // The registry entry records no caveat at all; the file is O's (its fingerprint matches).
  f.old.outPath = register(bytes); f.old.fingerprint = facts.fingerprint; f.old.caveats = []; save(f);
  const before = readFileSync(f.registry);
  const result = await invoke(f);
  failure(f, result, 3, 'S5');
  expect(result.error!.message).toContain('iprange');
  for (const text of wayOut) expect(result.error!.message).toContain(text);
  expect(f.calls).toEqual([]); unchanged(f, before);
}));

it('ROTATE-CAVEATS/S5 an expiry with its recorded duration is reproduced, so the stage proceeds as before', async () => scratch(async f => {
  f.old.caveats = [{ type: 'time-before', value: '2026-10-06T00:00:00Z', requested: '90d' }]; save(f);
  const result = await invoke(f); expect(result.error).toBeNull();
  const next = result.result!.new as Record<string, unknown>;
  expect(next.caveats).toEqual([{ type: 'time-before', value: '2027-01-03T09:00:00Z', requested: '90d' }]);
  expect(decodeMacaroon(new Secret(f.state.checked)).caveats).toEqual([{ type: 'time-before', value: '2027-01-03T09:00:00Z' }]);
  expect(f.lnd.bakeMacaroon).toHaveBeenCalledTimes(1); expect(f.rows()).toContainEqual(f.old);
}));

const bobId = 4294967400n;

it('ROTATE-CAVEATS/respond skips an IP-locked credential with a note and still rotates the others', async () => {
  const f = onlineFixture();
  const bob = onlineEntry(bobId, 'Bob');
  f.save([{ ...f.old, caveats: [{ type: 'ipaddr', value: '127.0.0.1' }] }, bob]);
  f.lnd.ids = [0n, onlineOwnId, onlineOldId, bobId];
  const outDir = declareStaging(join(f.dir, 'replacements'));
  const questions: string[] = [];
  f.deps.prompt = Object.assign(async (question: string) => { questions.push(question); return 'stage 1'; }, { isTTY: true });
  try {
    const plan = await respond(['--dry-run', ...f.flags], f.deps);
    expectSchemaValid(plan); expect(plan.error).toBeNull();
    expect((plan.result as RespondResult).items.map(item => [item.label, item.action, item.status]))
      .toEqual([['Alice', 'manual', 'manual'], ['Bob', 'stage', 'planned']]);
    const output = await respond(['--out-dir', outDir, ...f.flags], f.deps);
    expectSchemaValid(output); expect(output.error).toBeNull(); expect(output.exitCode).toBeUndefined();
    const result = output.result as RespondResult;
    expect(result.items.map(item => [item.label, item.action, item.status])).toEqual([['Alice', 'manual', 'manual'], ['Bob', 'stage', 'staged']]);
    const alice = result.items[0];
    expect(alice.note).toMatch(/ipaddr/);
    for (const text of wayOut) expect(alice.note).toContain(text);
    expect(alice.error).toBeNull(); expect(result.unproven).toEqual([]);
    expect(questions.at(-1)).toContain('Type "stage 1" to confirm');
    expect(f.lnd.baked).toHaveLength(1);
    expect(f.rows().find(row => row.replaces === String(onlineOldId))).toBeUndefined();
    expect(f.rows().find(row => row.replaces === String(bobId))).toMatchObject({ status: 'active', verified: true });
    const text = render(output, 'text');
    expect(text).toContain('ipaddr'); expect(text).toContain('macwarden attenuate');
  } finally { declareStagedFiles(); }
});

it('ROTATE-CAVEATS/inventory prints no rotate advice for an IP-locked credential', async () => {
  const f = onlineFixture();
  const soon = { type: 'time-before', value: '2026-10-07T00:00:00Z', requested: '30d' };
  f.save([{ ...f.old, caveats: [soon, { type: 'ipaddr', value: '127.0.0.1' }] }]);
  f.lnd.ids = [0n, onlineOwnId, onlineOldId];
  const output = await inventory(f.flags, f.deps);
  expectSchemaValid(output); expect(output.error).toBeNull();
  const text = render(output, 'text');
  expect(text).toMatch(new RegExp(`^${onlineOldId} .*expires in 1d$`, 'm'));
  expect(text).not.toContain('rotate with:');
  // Control: the same entry without the lock gets the advice.
  f.save([{ ...f.old, caveats: [soon] }]);
  expect(render(await inventory(f.flags, f.deps), 'text')).toContain('rotate with: macwarden rotate Alice');
});
