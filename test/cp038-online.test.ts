import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';
import { run as bake } from '../src/commands/bake/index.js';
import { run as rotate } from '../src/commands/rotate.js';
import { run as revoke } from '../src/commands/revoke.js';
import { run as inventory } from '../src/commands/inventory.js';
import { LndError } from '../src/errors.js';
import { render } from './helpers/render-adversarial.js';
import { fixture, type Fixture, oldId, pubkey } from './helpers/cp038-online.js';
import { revealSecret } from './helpers/secret-bytes.js';

type Mode = 'bake' | 'stage' | 'revoke' | 'finish' | 'inventory';
async function invoke(f: Fixture, mode: Mode, extra: string[] = []) {
  if (mode === 'inventory') return inventory([...f.flags, ...extra], f.deps);
  if (mode === 'bake') { f.save([]); return bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags, ...extra], f.deps); }
  if (mode === 'stage') return rotate(['Alice', '--out', f.out, ...f.flags, ...extra], f.deps);
  if (mode === 'finish') { f.save([f.old, f.next]); return rotate(['Alice', '--finish', '--yes', ...f.flags, ...extra], f.deps); }
  return revoke(['Alice', '--yes', ...f.flags, ...extra], f.deps);
}
function clean(f: Fixture) { expect(existsSync(f.registry + '.lock')).toBe(false); }

function replacementFault(f: Fixture, fail: () => ReturnType<Fixture['lnd']['checkMacaroon']>) {
  const original = f.lnd.checkMacaroon.bind(f.lnd);
  const oldBytes = readFileSync(f.old.outPath!);
  f.lnd.checkMacaroon = async (mac, permissions) => {
    if (Buffer.from(revealSecret(mac)).equals(oldBytes)) return original(mac, permissions);
    f.lnd.calls.push('CheckMacaroonPermissions');
    return fail();
  };
  return original;
}

it('CP-038/B6-bounded-files printed inventory revoke and rotate finish recovery preserves effective HTTPS port 443 and passes the command parser', async () => {
  for (const recoveryKind of ['inventory', 'revoke', 'finish'] as const) {
    const f = fixture();
    f.flags[f.flags.indexOf('--lnd-rest') + 1] = 'localhost:443';
    // Inject only documented adapter/filesystem failures after mutation.
    const listIds = f.lnd.listMacaroonIds.bind(f.lnd);
    if (recoveryKind === 'inventory') {
      f.lnd.listMacaroonIds = async () => {
        if (f.lnd.deleted.length) throw new LndError(4, 'transport', 'reconciliation unavailable');
        return listIds();
      };
    } else if (recoveryKind === 'revoke') {
      replacementFault(f, async () => ({ valid: false,
        reason: 'signature-mismatch', message: 'independent injected rejection' }));
    } else {
      f.deps.fs.rename = (async (...args: Parameters<typeof fs.rename>) => {
        if (f.lnd.deleted.length && String(args[1]) === f.registry)
          throw Object.assign(new Error('registry save unavailable'), { code: 'EIO' });
        return fs.rename(...args);
      }) as typeof fs.rename;
    }
    const failure = await invoke(f, recoveryKind === 'inventory' ? 'revoke'
      : recoveryKind === 'revoke' ? 'stage' : 'finish');
    expect(failure.error, recoveryKind).toMatchObject({ code: 7,
      step: recoveryKind === 'inventory' ? 'V12' : recoveryKind === 'revoke' ? 'S12' : 'F12' });
    clean(f);
    const printed = render(failure, 'text');
    const command = printed.match(/macwarden (?:inventory|revoke [A-Za-z0-9._-]+(?: --unregistered)?|rotate [A-Za-z0-9._-]+ --finish)(?: --(?:lnd-rest|tls-cert|macaroon|registry) (?:'[^']*'|"[^"]*"|[^\s`]+))+/)?.[0];
    expect(command, `${recoveryKind} printed recovery`).toBeDefined();
    // Tokenize the printed shell arguments; do not reconstruct the online flags.
    const tokens = [...command!.matchAll(/'([^']*)'|"([^"]*)"|([^\s]+)/g)]
      .map(match => match[1] ?? match[2] ?? match[3]!);
    const [executable, name, ...args] = tokens;
    expect(executable).toBe('macwarden');
    expect(name).toBe(recoveryKind === 'finish' ? 'rotate' : recoveryKind);
    if (recoveryKind === 'revoke') expect(args[0]).toBe(String(f.lnd.baked[0]));
    if (recoveryKind === 'finish') expect(args.slice(0, 2)).toEqual(['Alice', '--finish']);
    for (const flag of ['--lnd-rest', '--tls-cert', '--macaroon', '--registry']) {
      expect(args.filter(value => value === flag), `${recoveryKind} ${flag}`).toHaveLength(1);
      expect.soft(args[args.indexOf(flag) + 1], `${recoveryKind} ${flag}`)
        .toBe(f.flags[f.flags.indexOf(flag) + 1]);
    }
    f.lnd.listMacaroonIds = listIds;
    if (recoveryKind === 'revoke')
      f.lnd.checkMacaroon = Object.getPrototypeOf(f.lnd).checkMacaroon.bind(f.lnd);
    f.deps.fs.rename = fs.rename;
    const mutations = { baked: [...f.lnd.baked], deleted: [...f.lnd.deleted] };
    const callsBefore = f.lnd.calls.length;
    // run(args, deps) is the documented parser boundary, using env:{} and typed fakes.
    const replay = name === 'inventory' ? await inventory(args, f.deps)
      : name === 'revoke' ? await revoke([...args, '--dry-run'], f.deps)
        : await rotate([...args, '--dry-run'], f.deps);
    expect.soft(replay.error, `${recoveryKind} recovery parser`).toBeNull();
    expect.soft(f.lnd.calls.slice(callsBefore), `${recoveryKind} recovery reaches typed adapter`).toContain('GetInfo');
    expect(f.lnd.baked).toEqual(mutations.baked);
    expect(f.lnd.deleted).toEqual(mutations.deleted);
    clean(f);
  }
});

it.each(['grade', 'fingerprint', 'permissions'] as const)('CP-038/A2-rotate-privilege tampered %s refuses stage before issue', async kind => {
  const f = fixture();
  if (kind === 'grade') f.old.grade = 'READ';
  if (kind === 'fingerprint') f.old.fingerprint = 'fp:123456789abcdef0';
  if (kind === 'permissions') { f.old.permissions = [...f.old.permissions, 'offchain:write']; f.old.outPath = null; }
  f.save(); const before = readFileSync(f.registry);
  const result = await invoke(f, 'stage');
  expect(result.error).toMatchObject({ code: 3, step: 'S4' });
  expect(f.lnd.baked).toEqual([]); expect(f.lnd.deleted).toEqual([]);
  expect(readFileSync(f.registry).equals(before)).toBe(true); expect(existsSync(f.out)).toBe(false); clean(f);
});
it.each(['grade', 'fingerprint'] as const)('CP-038/A2-rotate-privilege tampered %s also refuses dry-run', async kind => {
  const f = fixture();
  if (kind === 'grade') f.old.grade = 'READ'; else f.old.fingerprint = 'fp:123456789abcdef0';
  f.save(); const result = await invoke(f, 'stage', ['--dry-run']);
  expect(result.error).toMatchObject({ code: 3, step: 'S4' }); expect(f.lnd.calls).toEqual([]); clean(f);
});
it('CP-038/A2-rotate-privilege dry-run displays reference grade and every permission', async () => {
  const f = fixture(); const result = await invoke(f, 'stage', ['--dry-run']);
  expect(result.error).toBeNull(); const text = render(result, 'text');
  expect(text).toContain('RECEIVE'); for (const permission of f.old.permissions) expect(text).toContain(permission);
  expect(f.lnd.baked).toEqual([]); expect(f.lnd.deleted).toEqual([]);
});
it.each(['bake', 'stage', 'inventory'] as const)('CP-038/A9-B1-typed-online %s accepts only normalized adapter success', async mode => {
  const f = fixture(); const result = await invoke(f, mode);
  expect(result.error).toBeNull(); expect(f.lnd.calls.filter(call => call === 'ListPermissions')).toHaveLength(1);
  if (mode !== 'inventory') expect(f.lnd.baked).toHaveLength(1);
  else expect(result.result).toMatchObject({ node: { pubkey, network: 'regtest' } });
  clean(f);
});
it.each([['bake', 'B8'], ['stage', 'S8'], ['revoke', 'V5'], ['finish', 'F5'], ['inventory', 'N4']] as const)(
  'CP-038/A9-B1-typed-online %s maps typed transport failure at %s', async (mode, step) => {
    const f = fixture(); f.lnd.infoFault = new LndError(4, 'transport', 'injected transport failure');
    const result = await invoke(f, mode); expect(result.error).toMatchObject({ code: 4, step });
    expect(f.lnd.baked).toEqual([]); expect(f.lnd.deleted).toEqual([]); clean(f);
  });
it.each([['bake', 'B14'], ['stage', 'S12']] as const)('CP-038/B3-primary-result %s unexpected verification throw preserves recovery at %s', async (mode, step) => {
  const f = fixture();
  const fail = async () => { throw new Error('private verification detail'); };
  if (mode === 'stage') replacementFault(f, fail);
  else f.lnd.verificationFault = new Error('private verification detail');
  const result = await invoke(f, mode); expect(result.error).toMatchObject({ code: 7, step });
  const id = f.lnd.baked[0]; expect(id).toBeDefined();
  expect(f.rows().find(row => row.rootKeyId === String(id))).toMatchObject({ verified: false, status: 'active', outPath: null,
    ...(mode === 'stage' ? { replaces: String(oldId) } : {}) });
  expect(result.error?.message).toContain(`macwarden revoke ${id}`);
  expect(result.error?.message).not.toContain('private verification detail'); expect(existsSync(f.out)).toBe(false); clean(f);
});
it.each(['success', 'verification-failure'] as const)('CP-038/B3-primary-result unlock failure does not replace %s', async kind => {
  const f = fixture();
  if (kind === 'verification-failure') f.lnd.verifyValid = false;
  f.deps.fs.unlink = (async (...args: Parameters<typeof fs.unlink>) => {
    if (String(args[0]) === f.registry + '.lock') throw Object.assign(new Error('cleanup detail'), { code: 'EIO' });
    return fs.unlink(...args);
  }) as typeof fs.unlink;
  const result = await invoke(f, 'bake');
  if (kind === 'success') expect(result.error?.code).toBe(7);
  else {
    expect(result.error).toMatchObject({ code: 7, step: 'B14' });
    expect(f.lnd.baked).toHaveLength(1);
    expect(result.error?.message).toContain(`macwarden revoke ${f.lnd.baked[0]}`);
    expect(f.rows().find(row => row.rootKeyId === String(f.lnd.baked[0])))
      .toMatchObject({ verified: false, outPath: null });
  }
  expect(render(result, 'text')).toMatch(/cleanup|unlock|lock.*fail/i);
  expect(render(result, 'text')).not.toContain('cleanup detail');
});
it('CP-038/B3-primary-result reserved-output discard failure retains verification recovery', async () => {
  const f = fixture();
  replacementFault(f, async () => ({ valid: false,
    reason: 'signature-mismatch', message: 'independent injected rejection' }));
  f.deps.fs.unlink = (async (...args: Parameters<typeof fs.unlink>) => {
    if (String(args[0]) === f.out) throw Object.assign(new Error('discard detail'), { code: 'EIO' });
    return fs.unlink(...args);
  }) as typeof fs.unlink;
  const result = await invoke(f, 'stage'); expect(result.error).toMatchObject({ code: 7, step: 'S12' });
  expect(result.error?.message).toContain(`macwarden revoke ${f.lnd.baked[0]}`);
});
it('CP-038/A5-cancellation pending identity exists before a potentially mutating bake', async () => {
  const f = fixture(); let pending: ReturnType<Fixture['rows']>[number] | undefined;
  f.lnd.onBake = id => {
    pending = f.rows().find(row => row.rootKeyId === String(id));
    throw new LndError(4, 'transport', 'lost response');
  };
  const result = await invoke(f, 'stage');
  expect(pending).toMatchObject({ nodePubkey: pubkey, rootKeyId: String(f.lnd.baked[0]),
    label: 'Alice', verified: false, status: 'active', outPath: null, replaces: String(oldId) });
  expect(result.error?.code).toBe(7);
  expect(result.error?.message).toContain(`macwarden revoke ${f.lnd.baked[0]}`); clean(f);
});
it.each(['revoke', 'finish'] as const)('CP-038/B6-bounded-files %s unusable optional baseline falls back to by-ID-only', async mode => {
  const f = fixture();
  f.deps.fs.open = (async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]) === f.old.outPath) throw Object.assign(new Error('unreadable baseline'), { code: 'EACCES' });
    return fs.open(...args);
  }) as typeof fs.open;
  f.deps.fs.readFile = (async (...args: Parameters<typeof fs.readFile>) => {
    if (String(args[0]) === f.old.outPath) throw Object.assign(new Error('unreadable baseline'), { code: 'EACCES' });
    return fs.readFile(...args);
  }) as typeof fs.readFile;
  const result = await invoke(f, mode); expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ evidence: 'by-id-only' }); expect(f.lnd.deleted).toEqual([oldId]); clean(f);
});
it('CP-038/B6-bounded-files oversized explicit target refuses at V3 before network', async () => {
  const f = fixture(), path = join(f.dir, 'large.macaroon'); writeFileSync(path, Buffer.alloc(1_048_577));
  const result = await invoke(f, 'revoke', ['--target-file', path]);
  expect(result.error).toMatchObject({ code: 3, step: 'V3' }); expect(f.lnd.calls).toEqual([]);
});
it('CP-038/B6-bounded-files explicit target uses bounded opened-handle reads', async () => {
  const f = fixture(); const wholeFile = vi.fn(async () => { throw new Error('unbounded read attempted'); });
  f.deps.fs.readFile = (async (...args: Parameters<typeof fs.readFile>) => {
    if (String(args[0]) === f.old.outPath) return wholeFile();
    return fs.readFile(...args);
  }) as typeof fs.readFile;
  const result = await invoke(f, 'revoke', ['--target-file', f.old.outPath!]);
  expect(wholeFile).not.toHaveBeenCalled(); expect(result.error?.step).not.toBe('V3');
});
it.each(['not-regular', 'replaced'] as const)('CP-038/B6-bounded-files opened explicit target %s refuses before content read', async kind => {
  const f = fixture(); let contentReads = 0;
  f.deps.fs.open = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    if (String(args[0]) !== f.old.outPath) return handle;
    return new Proxy(handle, { get(target, key) {
      if (key === 'stat') return async () => {
        const metadata = await target.stat();
        return new Proxy(metadata, { get(value, property) {
          if (property === 'isFile' && kind === 'not-regular') return () => false;
          if (property === 'ino' && kind === 'replaced') return Number(value.ino) + 1;
          const result: unknown = Reflect.get(value, property, value);
          return typeof result === 'function' ? result.bind(value) : result;
        } });
      };
      const value: unknown = Reflect.get(target, key, target);
      if ((key === 'read' || key === 'readFile') && typeof value === 'function') return (...params: unknown[]) => {
        contentReads++; return Reflect.apply(value, target, params);
      };
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  }) as typeof fs.open;
  const result = await invoke(f, 'revoke', ['--target-file', f.old.outPath!]);
  expect(result.error).toMatchObject({ code: 3, step: 'V3' }); expect(contentReads).toBe(0); expect(f.lnd.calls).toEqual([]);
});
it('CP-038/B6-bounded-files oversized TLS certificate refuses at OWN before network', async () => {
  const f = fixture(), path = join(f.dir, 'large.cert'); writeFileSync(path, Buffer.alloc(1_048_577));
  f.flags[f.flags.indexOf('--tls-cert') + 1] = path;
  const result = await invoke(f, 'bake'); expect(result.error).toMatchObject({ code: 4, step: 'B5' });
  expect(f.lnd.calls).toEqual([]); expect(existsSync(f.out)).toBe(false); clean(f);
});
it('CP-038/B7-spec-output inventory and revoke treat hexadecimal node identity consistently', async () => {
  const f = fixture(); f.lnd.info.pubkey = pubkey.toUpperCase();
  const listed = await invoke(f, 'inventory'); expect(listed.error).toBeNull();
  const rootKeys = (listed.result && 'rootKeys' in listed.result ? listed.result.rootKeys : undefined) as Array<{ rootKeyId: string; entry: unknown }>;
  expect(rootKeys.find(row => row.rootKeyId === String(oldId))?.entry).toMatchObject({ label: 'Alice' });
  const revoked = await invoke(f, 'revoke', ['--dry-run']); expect(revoked.error).toBeNull();
});
it.each(['bake', 'stage', 'revoke', 'finish', 'inventory'] as const)('CP-038/B7-spec-output %s refuses own stdin as usage before network', async mode => {
  const f = fixture(); f.flags[f.flags.indexOf('--macaroon') + 1] = '-';
  const stdin = vi.spyOn(process, 'stdin', 'get').mockReturnValue(Object.assign(Readable.from([]), { isTTY: false }) as typeof process.stdin);
  try {
    const result = await invoke(f, mode); expect(result.error?.code).toBe(2); expect(f.lnd.calls).toEqual([]);
    expect(f.lnd.baked).toEqual([]); expect(f.lnd.deleted).toEqual([]); clean(f);
  } finally { stdin.mockRestore(); }
});
it('CP-038/B7-spec-output inventory ENV refusal names N2', async () => {
  const f = fixture(); const result = await inventory(f.flags, { ...f.deps, env: { NODE_DEBUG: 'http' } });
  expect(result.error).toMatchObject({ code: 2, step: 'N2' }); expect(f.lnd.calls).toEqual([]);
});
it('CP-038/B7-spec-output inventory OWN failure names N2', async () => {
  const f = fixture(); f.flags[f.flags.indexOf('--macaroon') + 1] = join(f.dir, 'missing.macaroon');
  const result = await invoke(f, 'inventory'); expect(result.error).toMatchObject({ code: 4, step: 'N2' }); expect(f.lnd.calls).toEqual([]);
});
it('CP-038/B7-spec-output confirmation displays no completed-revocation sentence', async () => {
  const f = fixture(); let question = '';
  f.deps.prompt = Object.assign(async (value: string) => { question = value; return 'declined'; }, { isTTY: true });
  const result = await revoke(['Alice', ...f.flags], f.deps);
  expect(result.error?.code).toBe(6); expect(question).toContain('Alice');
  expect(question).not.toContain('No revocation performed.'); expect(f.lnd.deleted).toEqual([]);
});
