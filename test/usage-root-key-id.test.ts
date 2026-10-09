// MW110-07: a root key ID is a canonical decimal uint64 everywhere it is read: usage records,
// canary records, the registry and command selectors share one rule.
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { run as recommend } from '../src/commands/recommend.js';
import { openRegistry } from '../src/registry/index.js';
import { UsageStore, usagePath } from '../src/watch/usage.js';
import { expectSchemaValid } from './helpers/output-schema.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const PUBKEY = `02${'ab'.repeat(32)}`;
const MAX = '18446744073709551615';
const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as { methods: Record<string, string[]> };
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const accepted = ['0', '1', '18', '9999999999999999999', MAX];
const rejected = ['18446744073709551616', '99999999999999999999', '100000000000000000000', '00', '01', '0018',
  `0${MAX}`, '+1', '-1', '1e3', ' 1', '1 ', '0x10', '', '１２'];

const record = (rootKeyId: string) => ({ nodePubkey: PUBKEY, credential: 'id:1111111111111111', rootKeyId,
  method: '/lnrpc.Lightning/GetInfo', calls: 1, errors: 0, firstSeen: '2026-10-08T09:00:00Z', lastSeen: '2026-10-08T10:00:00Z' });
const canary = (rootKeyId: string) => ({ nodePubkey: PUBKEY, rootKeyId, uses: 1,
  firstUse: '2026-10-08T09:00:00Z', lastUse: '2026-10-08T10:00:00Z' });

it('USAGE/root-key-id usage and canary records accept exactly the canonical uint64 decimals', () => {
  for (const id of accepted) {
    expect(UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [record(id)] })).entries()[0].rootKeyId, id).toBe(id);
    expect(UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [], canaryUses: [canary(id)] }))
      .canaryUsesFor(PUBKEY, id), id).toMatchObject({ rootKeyId: id });
  }
  for (const id of rejected) {
    expect(() => UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [record(id)] })), `entry ${id}`)
      .toThrow('invalid usage file');
    expect(() => UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [], canaryUses: [canary(id)] })), `canary ${id}`)
      .toThrow('invalid usage file');
  }
});

it('USAGE/root-key-id watch never records an ID the reader would refuse, so its file always reads back', () => {
  const store = new UsageStore();
  const at = new Date('2026-10-08T12:00:00Z');
  for (const id of rejected) {
    expect(store.record(PUBKEY, 'id:1111111111111111', id, '/lnrpc.Lightning/GetInfo', at), id).toBe(false);
    store.recordCanary(PUBKEY, id, 1, at);
    expect(store.canaryUsesFor(PUBKEY, id), id).toBeNull();
  }
  expect(store.record(PUBKEY, 'id:1111111111111111', MAX, '/lnrpc.Lightning/GetInfo', at)).toBe(true);
  store.recordCanary(PUBKEY, MAX, 1, at);
  const copy = UsageStore.parse(store.toText());
  expect(copy.entries().map(item => item.rootKeyId)).toEqual([MAX]);
  expect(copy.canaryUsesFor(PUBKEY, MAX)).toMatchObject({ uses: 1 });
});

function setup(entries: object[] = [], usage: object[] = []) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'root-key-id-'));
  dirs.push(dir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries }));
  writeFileSync(usagePath(registry), JSON.stringify({ schema: 1, dropped: 0, entries: usage }));
  writeFileSync(join(dir, 'tls.cert'), 'unused');
  writeFileSync(join(dir, 'own.macaroon'), readFileSync(join(repo, 'test/vectors/default-admin.macaroon')));
  const deps = { lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'a', network: 'regtest', version: 'v' }),
    listPermissions: async () => snapshot.methods } as never, fs, env: {} };
  return { registry, deps, args: ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry, '--json'] };
}

it('RECOMMEND/root-key-id a selector above uint64 is refused like any other malformed selector', async () => {
  const s = setup([], [record(MAX)]);
  for (const id of ['18446744073709551616', '99999999999999999999', '00', '0018']) {
    const result = await recommend([id, ...s.args], s.deps);
    expectSchemaValid(result);
    expect(result, id).toMatchObject({ ok: false, error: { code: 2, step: 'R1' } });
  }
  const max = await recommend([MAX, ...s.args], s.deps);
  expectSchemaValid(max);
  expect(max).toMatchObject({ ok: true, result: { rootKeyId: MAX, credentials: ['id:1111111111111111'] } });
});

it('REGISTRY/root-key-id the registry applies the same rule to rootKeyId, replaces and replacedBy', async () => {
  const entry = (rootKeyId: string, link: Record<string, string | null> = {}) => ({ nodePubkey: PUBKEY, label: null, rootKeyId,
    permissions: ['info:read'], caveats: [], grade: 'READ', fingerprint: null, outPath: null, createdAt: '2026-10-01T00:00:00Z',
    verified: false, status: 'revoked', revokedAt: '2026-10-02T00:00:00Z', revokeEvidence: 'by-id-only', replaces: null, replacedBy: null, ...link });
  const open = async (entries: object[]) => { const s = setup(entries); return openRegistry(s.registry, { fs }); };
  await expect(open([entry(MAX), entry('1', { replaces: MAX, replacedBy: MAX })])).resolves.toBeDefined();
  for (const id of ['18446744073709551616', '99999999999999999999', '00', '0018']) {
    await expect(open([entry(id)]), id).rejects.toThrow('invalid registry');
    await expect(open([entry('1', { replaces: id })]), id).rejects.toThrow('invalid registry');
    await expect(open([entry('1', { replacedBy: id })]), id).rejects.toThrow('invalid registry');
  }
});
