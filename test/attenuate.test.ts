import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';
import { run as attenuate } from '../src/commands/attenuate.js';
import { run as inspect } from '../src/commands/inspect.js';
import { canonicalCidr, canonicalIp } from '../src/caveat-address.js';
import { render } from '../src/output/index.js';

// Owner request 2026-10-07: offline attenuation. Titles use the ATTENUATE/ prefix
// because no checkpoint contract covers this command yet.
const repo = resolve();
const tmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const instant = new Date('2026-10-05T09:00:00.000Z');
const vector = (name: string) => join(repo, 'test/vectors', `${name}.macaroon`);
const deps = (stdin: Buffer | null = null) => ({
  stdin: Object.assign(stdin ? Readable.from([stdin]) : Readable.from([]), { isTTY: stdin === null }),
  fs, env: {}, clock: () => instant,
});

async function scratch<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(tmp, { recursive: true });
  const dir = mkdtempSync(join(tmp, 'attenuate-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

// Independent macaroon v2 binary layout (go-macaroon), not the product encoder.
const varint = (value: number) => {
  const bytes: number[] = [];
  do { bytes.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
  return Buffer.from(bytes);
};
const field = (kind: number, bytes: Buffer) => Buffer.concat([varint(kind), varint(bytes.length), bytes]);
const proto = (kind: number, bytes: Buffer) => field(kind * 8 + 2, bytes);
const hmac = (key: Buffer, data: Buffer) => createHmac('sha256', key).update(data).digest();

function knownRootKeyMacaroon(rootKey: Buffer, id: bigint, permissions: string[]): { bytes: Buffer; identifier: Buffer; signature: Buffer } {
  const ops = permissions.map(permission => {
    const at = permission.indexOf(':');
    return proto(3, Buffer.concat([proto(1, Buffer.from(permission.slice(0, at))), proto(2, Buffer.from(permission.slice(at + 1)))]));
  });
  const identifier = Buffer.concat([Buffer.from([3]), proto(1, Buffer.alloc(16, 7)), proto(2, Buffer.from(String(id))), ...ops]);
  // go-macaroon: the signing key is HMAC("macaroons-key-generator", rootKey); sig0 = HMAC(key, id).
  const signature = hmac(hmac(Buffer.from('macaroons-key-generator'), rootKey), identifier);
  const bytes = Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier), Buffer.from([0]),
    Buffer.from([0]), field(6, signature)]);
  return { bytes, identifier, signature };
}

it('ATTENUATE/A5-hmac-chain appended caveats follow the go-macaroon v2 layout and HMAC chain from a known root key', async () => scratch(async dir => {
  const rootKey = Buffer.alloc(32, 0x5a);
  const parent = knownRootKeyMacaroon(rootKey, 4242n, ['info:read', 'invoices:read']);
  const input = join(dir, 'parent.macaroon'), out = join(dir, 'child.macaroon');
  writeFileSync(input, parent.bytes);
  const result = await attenuate([input, '--out', out, '--expires', '90m', '--ip-range', '10.1.2.3/8'], deps());
  expect(result.error).toBeNull();
  const conditions = ['time-before 2026-10-05T10:30:00Z', 'iprange 10.0.0.0/8'].map(text => Buffer.from(text));
  const signature = conditions.reduce((sig, condition) => hmac(sig, condition), parent.signature);
  const expected = Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, parent.identifier), Buffer.from([0]),
    ...conditions.map(condition => Buffer.concat([field(2, condition), Buffer.from([0])])),
    Buffer.from([0]), field(6, signature)]);
  expect(readFileSync(out).equals(expected)).toBe(true);
  expect(result.result).toMatchObject({ rootKeyId: '4242', added: conditions.map(String), out: resolve(out), dryRun: false });
}));

it.each(['default-readonly', 'time-before', 'time-nanosecond', 'ipaddr', 'iprange', 'lnd-custom', 'third-party', 'unknown-condition'])(
  'ATTENUATE/A5-equal-plus %s child decodes to the input facts plus the appended caveats', async name => scratch(async dir => {
    const out = join(dir, 'child.macaroon');
    const before = (await inspect([vector(name), '--json'], deps())).result as { rootKeyId: string; permissions: string[]; caveats: { type: string; value: string }[] };
    const result = await attenuate([vector(name), '--out', out, '--expires', '2h'], deps());
    expect(result.error).toBeNull();
    const after = (await inspect([out], deps())).result as typeof before;
    expect(after.rootKeyId).toBe(before.rootKeyId);
    expect(after.permissions).toEqual(before.permissions);
    expect(after.caveats.map(({ type, value }) => ({ type, value })))
      .toEqual([...before.caveats.map(({ type, value }) => ({ type, value })), { type: 'time-before', value: '2026-10-05T11:00:00Z' }]);
  }));

it.each([
  ['127.0.0.1', '127.0.0.1'], ['0.0.0.0', '0.0.0.0'],
  ['2001:0DB8:0000:0000:0000:0000:0000:0001', '2001:db8::1'], ['::', '::'], ['::1', '::1'],
  ['1:0:0:2:0:0:0:3', '1:0:0:2::3'], ['1:0:0:2:0:0:3:4', '1::2:0:0:3:4'], ['1:0:2:3:4:5:6:7', '1:0:2:3:4:5:6:7'],
  ['::1.2.3.4', '::102:304'], ['fe80::', 'fe80::'], ['1:2:3:4:5:6:1.2.3.4', '1:2:3:4:5:6:102:304'], ['1::1.2.3.4', '1::102:304'],
])('ATTENUATE/A1-ip-canonical %s is written as Go net.IP.String %s', (input, expected) => {
  expect(canonicalIp(input)).toBe(expected);
});

it.each([
  ['10.1.2.3/8', '10.0.0.0/8'], ['192.168.1.77/32', '192.168.1.77/32'], ['0.0.0.0/0', '0.0.0.0/0'],
  ['127.0.0.1/8', '127.0.0.0/8'], ['2001:db8::ff/64', '2001:db8::/64'], ['2001:db8:1:2:3:4:5:6/127', '2001:db8:1:2:3:4:5:6/127'],
  ['::/0', '::/0'],
])('ATTENUATE/A1-iprange-canonical %s is written as Go net.IPNet.String %s', (input, expected) => {
  expect(canonicalCidr(input)).toBe(expected);
});

it.each([
  [['--out', 'x'], /at least one caveat/],
  [['--expires', '1h'], /--out is required/],
  [['--out', 'x', '--ip', '1.2.3.4', '--ip-range', '1.2.3.0/24'], /mutually exclusive/],
  [['--out', 'x', '--out', 'y', '--expires', '1h'], /--out was given more than once/],
  [['--out', 'x', '--expires', '0h'], /--expires must be 1 to 99999 followed by m/], [['--out', 'x', '--expires', '1w'], /--expires must be 1 to 99999 followed by m/],
  [['--out', 'x', '--expires', '100000d'], /--expires must be 1 to 99999 followed by m/], [['--out', 'x', '--bogus'], /unknown flag/],
  ...['01.2.3.4', '1.2.3', '256.1.1.1', '::ffff:1.2.3.4', 'fe80::1%eth0', '1:2:3:4:5:6:7:8:9', '1::2::3', '1:2:3:4:5:6:7::8', 'localhost', '',
    // Go net.ParseIP returns nil: an embedded IPv4 address must be the final 32 bits.
    '1.2.3.4::', '1.2.3.4::1', '1:1.2.3.4::', '1.2.3.4:1:2:3:4:5:6']
    .map(ip => [['--out', 'x', '--ip', ip], /invalid --ip|missing value/] as [string[], RegExp]),
  ...['10.0.0.0/33', '10.0.0.0/08', '::/129', '10.0.0.0', '10.0.0.0/8/8', 'a.b.c.d/8', '1.2.3.4::/16', '1.2.3.4::1/64']
    .map(range => [['--out', 'x', '--ip-range', range], /invalid --ip-range/] as [string[], RegExp]),
])('ATTENUATE/A1-refusal %j exits 2 before reading input or creating output', async (flags, message) => scratch(async dir => {
  const args = flags.map(item => item === 'x' || item === 'y' ? join(dir, item) : item);
  const result = await attenuate([vector('default-readonly'), ...args], deps());
  expect(result.error).toMatchObject({ code: 2, step: 'A1' }); expect(result.error!.message).toMatch(message);
  expect(existsSync(join(dir, 'x'))).toBe(false); expect(existsSync(join(dir, 'y'))).toBe(false);
}));

it('ATTENUATE/A4-undecodable input exits 3 and creates no output', async () => scratch(async dir => {
  const input = join(dir, 'bad.macaroon'), out = join(dir, 'child.macaroon');
  writeFileSync(input, Buffer.from('0201036c6e6400', 'hex'));
  const result = await attenuate([input, '--out', out, '--expires', '1h'], deps());
  expect(result.error?.code).toBe(3); expect(existsSync(out)).toBe(false);
  const missing = await attenuate([join(dir, 'absent.macaroon'), '--out', out, '--expires', '1h'], deps());
  expect(missing.error?.code).toBe(3); expect(existsSync(out)).toBe(false);
}));

it('ATTENUATE/A3-output existing or protected output is refused and never overwritten', async () => scratch(async dir => {
  const out = join(dir, 'child.macaroon');
  writeFileSync(out, 'keep');
  const existing = await attenuate([vector('default-readonly'), '--out', out, '--expires', '1h'], deps());
  expect(existing.error).toMatchObject({ code: 3, step: 'A3' }); expect(readFileSync(out, 'utf8')).toBe('keep');
  for (const name of ['wallet.db', 'macaroons.db', 'tls.key']) {
    const protectedOut = await attenuate([vector('default-readonly'), '--out', join(dir, name), '--expires', '1h'], deps());
    expect(protectedOut.error).toMatchObject({ code: 3, step: 'A3' }); expect(existsSync(join(dir, name))).toBe(false);
  }
}));

it('ATTENUATE/A6-owner-only output is created owner-only through the shared bake writer', async () => scratch(async dir => {
  const out = join(dir, 'child.macaroon');
  const result = await attenuate([vector('default-readonly'), '--out', out, '--ip', '127.0.0.1'], deps());
  expect(result.error).toBeNull();
  if (process.platform === 'win32') {
    expect(result.warnings).not.toContain('acl-best-effort');
    // Independent proof: System32 icacls saves the file's ACL and System32 whoami names the user.
    const systemRoot = process.env.SystemRoot;
    if (!systemRoot) throw new Error('Windows SystemRoot is required');
    const acl = join(dir, 'acl.txt');
    const saved = spawnSync(join(systemRoot, 'System32', 'icacls.exe'), [out, '/save', acl], { encoding: 'utf8', timeout: 10_000 });
    expect(saved.status).toBe(0);
    const whoami = spawnSync(join(systemRoot, 'System32', 'whoami.exe'), ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', timeout: 10_000 });
    expect(whoami.status).toBe(0);
    const sid = whoami.stdout.trim().split(',').at(-1)!.replaceAll('"', '');
    expect(sid).toMatch(/^S-1-\d+(?:-\d+)+$/);
    const text = readFileSync(acl).toString('utf16le');
    expect(text).toContain('D:P'); // protected: nothing inherited from the folder
    expect(text.match(/\(A;[^)]*\)/g)).toEqual([`(A;;FA;;;${sid})`]);
  } else expect(statSync(out).mode & 0o777).toBe(0o600);
}));

it('ATTENUATE/A6-dry-run reports the child facts and writes nothing', async () => scratch(async dir => {
  const out = join(dir, 'child.macaroon');
  const result = await attenuate([vector('default-readonly'), '--out', out, '--expires', '1h', '--dry-run'], deps());
  expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ dryRun: true, out: null, added: ['time-before 2026-10-05T10:00:00Z'] });
  expect(existsSync(out)).toBe(false);
}));

it('ATTENUATE/A4-stdin reads the input from standard input', async () => scratch(async dir => {
  const out = join(dir, 'child.macaroon');
  const result = await attenuate(['-', '--out', out, '--expires', '1h'], deps(readFileSync(vector('default-readonly'))));
  expect(result.error).toBeNull(); expect(existsSync(out)).toBe(true);
}));

it('ATTENUATE/A5-warnings shared root key always, REST proxy only for IP caveats, earlier expiry and existing IP caveats', async () => scratch(async dir => {
  const codes = async (name: string, flags: string[], out: string) => {
    const result = await attenuate([vector(name), '--out', join(dir, out), ...flags], deps());
    expect(result.error).toBeNull();
    return result.warnings.map(item => typeof item === 'string' ? item : item.code);
  };
  expect(await codes('default-readonly', ['--expires', '1h'], 'a')).toEqual(['shared-root-key', 'expiry-clock']);
  expect(await codes('default-readonly', ['--ip', '127.0.0.1'], 'b')).toEqual(['shared-root-key', 'ip-caveat-rest-proxy']);
  // time-before vector expires 2026-10-02, before the fixed clock: the earlier expiry still applies.
  expect(await codes('time-before', ['--expires', '1h'], 'c')).toContain('earlier-expiry-kept');
  expect(await codes('time-nanosecond', ['--expires', '1h'], 'd')).not.toContain('earlier-expiry-kept');
  expect(await codes('ipaddr', ['--ip-range', '10.0.0.0/8'], 'e')).toContain('existing-ip-caveat');
}));

it('ATTENUATE/A6-output text and JSON carry facts and fingerprints, never credential bytes', async () => scratch(async dir => {
  const out = join(dir, 'child.macaroon');
  const result = await attenuate([vector('default-admin'), '--out', out, '--expires', '1h'], deps());
  expect(result.error).toBeNull();
  const child = readFileSync(out), parent = readFileSync(vector('default-admin'));
  for (const text of [render(result, 'text'), render(result, 'json')]) {
    expect(text).toMatch(/fp:[0-9a-f]{16}/);
    for (const bytes of [child, parent]) for (const encoding of ['hex', 'base64', 'base64url'] as const) {
      expect(text).not.toContain(bytes.toString(encoding).slice(0, 40));
    }
  }
  expect(render(result, 'text')).toMatch(/root key ID\s+0/);
}));
