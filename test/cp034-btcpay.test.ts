import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { render } from './helpers/render-adversarial.js';
import { fixture } from './helpers/cp025-bake-support.mjs';
import { manifest, suite, validateManifest } from './helpers/cp034-btcpay.mjs';

type Envelope = { ok: boolean; result: Record<string, unknown> | null;
  warnings: Array<string | { code: string }>; error: { code: number; step: string; message: string } | null };
const ownSuite = suite('unit');
afterAll(() => {
  process.env.MACWARDEN_TEST_TMP = ownSuite.previous.tmp;
  if (ownSuite.previous.sentinels === undefined) delete process.env.MACWARDEN_SENTINEL_DIR;
  else process.env.MACWARDEN_SENTINEL_DIR = ownSuite.previous.sentinels;
  rmSync(ownSuite.dir, { recursive: true, force: true });
});
async function scenario(work: (f: ReturnType<typeof fixture>) => Promise<void>, dry = true) {
  const dir = mkdtempSync(join(ownSuite.dir, 'case-'));
  const f = fixture(dir, Secret, 'btcpay');
  f.args[f.args.indexOf('--preset') + 1] = 'btcpay';
  writeFileSync(f.registry, '{"schema":1,"entries":[]}', { mode: 0o600 });
  if (dry) f.lnd.getInfo = async () => {
    f.state.calls.push('GetInfo');
    return { alias: 'fixture', version: '0.21.4-beta', pubkey: '02' + 'ab'.repeat(32), network: 'regtest' };
  };
  try { await work(f); } finally { rmSync(dir, { recursive: true, force: true }); }
}
async function invoke(f: ReturnType<typeof fixture>, dry = true): Promise<Envelope> {

  const command = await import('../src/commands/bake/index.js') as {
    run: (args: string[], deps: unknown) => Promise<Envelope> };
  const result = await command.run([...f.args, ...(dry ? ['--dry-run'] : [])], f.deps);
  ownSuite.outputs.push(render(result, 'json'), render(result, 'text'));
  expect(result.error, 'btcpay must be a recognized source-backed preset').toBeNull();
  return result;
}

it('CP-034/btcpay-source-map exact preset set covers every independently attributed client call', async () => {
  validateManifest();
  // Attribution failure is explicit; deleting a call cannot turn this oracle green.
  const omitted = structuredClone(manifest); omitted.calls.pop();
  expect(() => validateManifest(omitted)).toThrow(/omitted|differs/);
  const unmapped = structuredClone(manifest); unmapped.calls[0].permissionsSource.text = '';
  expect(() => validateManifest(unmapped)).toThrow(/permission source/);
  await scenario(async f => {
    const result = await invoke(f);
    expect((result.result!.permissions as string[]).slice().sort()).toEqual(manifest.permissions);
  });
});

it('CP-034/btcpay-grade source-backed authority is displayed as SPEND without unassessed warnings', async () => {
  await scenario(async f => {
    const result = await invoke(f);

    const { grade } = await import('../src/grade/index.js') as {
      grade: (permissions: string[]) => { grade: string; warnings: string[]; unassessed: string[]; reasons: string[] } };
    const assessed = grade(manifest.permissions);
    expect(assessed).toMatchObject({ grade: 'SPEND', unassessed: [] });
    expect(assessed.reasons).toEqual(['uri:/lnrpc.Lightning/OpenChannelSync', 'uri:/routerrpc.Router/SendPaymentV2']);
    expect(assessed.warnings.some(warning => warning.startsWith('unassessed-'))).toBe(false);
    expect(result.result!.grade).toBe(assessed.grade);
    expect(render(result, 'text')).toContain('SPEND');
    expect(result.warnings.map(warning => typeof warning === 'string' ? warning : warning.code)
      .some(warning => warning.startsWith('unassessed-'))).toBe(false);
  });
});

it('CP-034/btcpay-bake exact permissions reach bake and final bytes match the active registry fingerprint', async () => {
  await scenario(async f => {
    const before = [...f.state.ids];
    let requested: string[] = [];
    const bake = f.lnd.bakeMacaroon;
    f.lnd.bakeMacaroon = async (permissions: string[], id: bigint) => {
      requested = [...permissions]; return bake(permissions, id);
    };
    const result = await invoke(f, false);
    expect(requested.slice().sort()).toEqual(manifest.permissions);
    const entry = result.result!;
    expect(entry.rootKeyId).toMatch(/^[1-9][0-9]*$/);
    expect(before).not.toContain(entry.rootKeyId);
    const bytes = readFileSync(f.out);
    expect(bytes.equals(f.state.checked!)).toBe(true);
    expect(entry).toMatchObject({ fingerprint: `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`,
      grade: 'SPEND', verified: true, status: 'active', outPath: f.out });
    expect(JSON.parse(readFileSync(f.registry, 'utf8')).entries).toEqual([entry]);
    if (process.platform !== 'win32') expect(statSync(f.out).mode & 0o777).toBe(0o600);
    expect(f.state.calls).toContain('CheckMacaroonPermissions');
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    expect(ownSuite.leak()).toBeNull();
  }, false);
});

it('CP-034/btcpay-dry-run exact plan allocates nothing and preserves registry, IDs and out state', async () => {
  await scenario(async f => {
    const registry = readFileSync(f.registry), ids = [...f.state.ids];
    const result = await invoke(f);
    expect(result.result).toMatchObject({ dryRun: true, label: 'btcpay', grade: 'SPEND', caveats: [] });
    expect((result.result!.permissions as string[]).slice().sort()).toEqual(manifest.permissions);
    expect(render(result, 'text')).toContain('root key ID: allocated at bake time');
    expect(f.state.calls).toEqual(['GetInfo', 'ListPermissions']);
    expect(f.state.ids).toEqual(ids);
    expect(readFileSync(f.registry).equals(registry)).toBe(true);
    expect(existsSync(f.out)).toBe(false);
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    expect(ownSuite.leak()).toBeNull();
  });
});
