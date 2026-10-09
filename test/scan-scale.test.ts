import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { Cancelled, withCancellation } from '../src/cancellation.js';
import { redactEncodedCredentials } from '../src/credential-recognition.js';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { readBounded, scan } from '../src/scan/index.js';
import { knownSecretRedactor } from '../src/scan/redact.js';
import { childEnvironment } from './helpers/environment.js';

// Scale and robustness audit of 2026-10-07 (owner-delegated fixes). Titles use the
// SCALE/ prefix: no checkpoint contract owns these cases. Every timing bound is several
// times the measured new cost and far below the measured old cost (noted per test).
const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
const scanSchema = ajv.compile(JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));
const fp = (text: string | Buffer) => `fp:${createHash('sha256').update(text).digest('hex').slice(0, 16)}`;

function temp<T>(prefix: string, body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, prefix));
  return body(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function git(dir: string, ...args: string[]): string {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
  return run.stdout.trim();
}

/** A history with `commits` commits of `files` small text files each, written by fast-import. */
function bulkHistory(dir: string, commits: number, files: number, line: (c: number, f: number) => string): void {
  git(dir, 'init', '-q');
  let stream = '';
  for (let c = 0; c < commits; c++) {
    stream += `commit refs/heads/main\ncommitter t <t@example.invalid> ${1_700_000_000 + c} +0000\ndata 1\nc\n`;
    for (let f = 0; f < files; f++) {
      const body = `${line(c, f)}\n`;
      stream += `M 100644 inline d${f % 50}/f${f}.txt\ndata ${Buffer.byteLength(body)}\n${body}\n`;
    }
  }
  const run = spawnSync('git', ['fast-import', '--quiet'], { cwd: dir, input: stream, maxBuffer: 64 * 1024 * 1024 });
  if (run.status !== 0) throw new Error(`fast-import failed: ${run.stderr}`);
  git(dir, 'checkout', '-q', 'main');
}

// The previous known-secret redaction, kept verbatim as the reference behaviour.
function reference(text: string, secrets: ReadonlySet<string>): string {
  let safe = text;
  for (const hex of secrets) {
    const bytes = Buffer.from(hex, 'hex');
    const variants = new Set([
      bytes.toString('base64'), bytes.toString('base64').replace(/=+$/, ''),
      bytes.toString('base64url'), bytes.toString('base64url').replace(/=+$/, ''),
      bytes.toString('latin1'),
    ]);
    const utf8 = bytes.toString('utf8');
    if (Buffer.from(utf8, 'utf8').equals(bytes)) variants.add(utf8);
    safe = safe.replace(new RegExp([...hex].join('[ \\t\\r\\n]*'), 'gi'), '[redacted]');
    for (const variant of [...variants].sort((a, b) => b.length - a.length)) {
      if (!variant || variant === hex) continue;
      safe = safe.replaceAll(variant, '[redacted]');
      if (variant.length >= 40) {
        const wrapped = [...variant].map(character => character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
          .join('(?:\\r?\\n)?');
        safe = safe.replace(new RegExp(wrapped, 'g'), '[redacted]');
      }
    }
  }
  return safe;
}

function seeded(seed: number): () => number {
  let state = seed >>> 0;
  return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 2 ** 32; };
}

/** Text embedding every redacted form of the secrets, with wrapping, case and near misses. */
function corpus(secrets: string[], random: () => number): string[] {
  const pick = <T>(values: T[]) => values[Math.floor(random() * values.length)];
  const wrap = (value: string, gaps: string[]) => [...value].map((ch, i) => i && random() < 0.08 ? pick(gaps) + ch : ch).join('');
  const out: string[] = [];
  for (const hex of secrets) {
    const bytes = Buffer.from(hex, 'hex');
    const forms = [
      hex, hex.toUpperCase(), wrap(hex, [' ', '\t', '\n', '\r\n', '  \n ']),
      bytes.toString('base64'), bytes.toString('base64').replace(/=+$/, ''), bytes.toString('base64url'),
      wrap(bytes.toString('base64'), ['\n', '\r\n']), wrap(bytes.toString('base64url'), ['\n', '\r\n']),
      wrap(bytes.toString('base64'), ['\n\n', '\r']), // gaps the wrapped form does not allow
      bytes.toString('latin1'), hex.slice(0, 63), bytes.toString('base64').slice(1),
    ];
    for (let n = 0; n < 4; n++) {
      out.push(`caveat ${pick(['x', 'uri ', '%', ''])}${pick(forms)}${pick(['', ' tail', '\n', 'Z'])}${pick(forms).slice(0, 20)}`);
    }
  }
  return out;
}

it('SCALE/known-secrets one matcher redacts exactly what the per-secret passes did', () => {
  const random = seeded(7);
  const secrets = Array.from({ length: 40 }, (_, i) => {
    // Every eighth secret is ASCII-only, so its UTF-8 form is also a redacted variant.
    const bytes = i % 8 === 0 ? Buffer.from(Array.from({ length: 32 }, () => 0x20 + Math.floor(random() * 0x5f)))
      : Buffer.from(Array.from({ length: 32 }, () => Math.floor(random() * 256)));
    return bytes.toString('hex');
  });
  const set = new Set(secrets);
  const redact = knownSecretRedactor(set);
  let changed = 0;
  for (const text of corpus(secrets, random)) {
    const expected = reference(text, set);
    if (expected !== text) changed++;
    expect(redact(text)).toBe(expected);
  }
  expect(changed).toBeGreaterThan(100);
});

it('SCALE/known-secrets cost does not multiply secrets by text (old: about 100 s for 2,000 x 2,000)', () => {
  const secrets = Array.from({ length: 2000 }, () => randomBytes(32).toString('hex'));
  const set = new Set(secrets);
  const texts = Array.from({ length: 2000 }, (_, i) => `/repo/dir-${i}/nostr-${secrets[i].slice(0, 10)}.env caveat value ${i}`
    + (i % 100 === 0 ? ` ${secrets[i]}` : ''));
  const started = performance.now();
  const redact = knownSecretRedactor(set);
  const output = texts.map(redact);
  expect(performance.now() - started).toBeLessThan(10_000);
  expect(output.filter(text => text.includes('[redacted]'))).toHaveLength(20);
  // A single 1 MiB string with many secrets is also linear.
  const big = `${'a b c '.repeat(170_000)}${secrets[5]}`;
  const once = performance.now();
  expect(redact(big).endsWith('[redacted]')).toBe(true);
  expect(performance.now() - once).toBeLessThan(5_000);
});

it('SCALE/render-fast-path printable ASCII shorter than 36 characters is never changed by recognition', () => {
  // The renderer returns such strings without running recognition; this property is what
  // makes that safe. Truncations of real credential encodings are the hardest cases.
  const random = seeded(11);
  const sources: string[] = [];
  for (const name of ['default-admin', 'default-readonly', 'time-before']) {
    const bytes = vector(name);
    sources.push(bytes.toString('hex'), bytes.toString('base64'), bytes.toString('base64url'),
      [...bytes].map(byte => `%${byte.toString(16).padStart(2, '0')}`).join(''), [...bytes].join(','));
    // The full encodings are recognized (the property is not vacuous).
    expect(redactEncodedCredentials(bytes.toString('hex'))).toBe('[redacted]');
  }
  let checked = 0;
  for (const source of sources) {
    for (let start = 0; start < Math.min(source.length, 400); start += 7) {
      for (const length of [1, 8, 20, 35]) {
        const text = source.slice(start, start + length);
        expect(redactEncodedCredentials(text)).toBe(text);
        checked++;
      }
    }
  }
  for (let n = 0; n < 2000; n++) {
    const text = Array.from({ length: 1 + Math.floor(random() * 35) }, () => String.fromCharCode(0x20 + Math.floor(random() * 0x5f))).join('');
    expect(redactEncodedCredentials(text)).toBe(text);
    checked++;
  }
  expect(checked).toBeGreaterThan(3000);
});

it('SCALE/render-speed 100,000 findings render as JSON well under the old 0.3 ms per finding', () => {
  const findings = Array.from({ length: 100_000 }, (_, i) => ({
    path: `/srv/app/config-${i % 400}/settings-${i}.env`, line: i + 1, column: 1, kind: 'undecodable-candidate',
    fingerprint: fp(String(i)), grade: null, rootKeyId: null, permissions: null, caveats: null, warnings: [], unassessed: [],
  }));
  const result = { command: 'scan', ok: true, warnings: [], error: null, result: { findings, skipped: [],
    summary: { filesScanned: 1, filesSkipped: 0, dropped: 0, ignored: 0, findings: findings.length, distinct: findings.length,
      byGrade: { ADMIN: 0, SPEND: 0, OPERATE: 0, RECEIVE: 0, READ: 0, UNASSESSED: 0, NWC: 0, UNDECODABLE: findings.length, L402: 0 } },
    failOn: null } } as unknown as OutputResult;
  const started = performance.now();
  let length = 0;
  for (const chunk of renderChunks(result, 'json')) length += chunk.length;
  // Measured under load: 2.8 s now, 11.7 s before.
  expect(performance.now() - started).toBeLessThan(7_000);
  expect(length).toBeGreaterThan(15_000_000);
});

it('SCALE/read-bounded a small file gets a small buffer; growth and the limit are still honoured', async () => {
  const handle = (content: Buffer) => {
    const sizes: number[] = [];
    return { sizes, read: async (buffer: Buffer, offset: number, length: number, position: number) => {
      sizes.push(buffer.length);
      const bytesRead = Math.max(0, Math.min(length, content.length - position));
      content.copy(buffer, offset, position, position + bytesRead);
      return { bytesRead, buffer };
    } };
  };
  const small = handle(Buffer.from('x'.repeat(100)));
  expect((await readBounded(small as never, 5_242_880, 100n)).length).toBe(100);
  expect(Math.max(...small.sizes)).toBe(101);
  // fstat said 10 bytes but the file grew to 50,000: everything is read.
  const grown = handle(Buffer.alloc(50_000, 7));
  expect((await readBounded(grown as never, 5_242_880, 10n)).equals(Buffer.alloc(50_000, 7))).toBe(true);
  // Never more than limit + 1 bytes, whatever fstat said.
  const large = handle(Buffer.alloc(9_000, 1));
  expect((await readBounded(large as never, 4_000, 20_000n)).length).toBe(4_001);
  const lying = handle(Buffer.alloc(9_000, 1));
  expect((await readBounded(lying as never, 4_000, 1n)).length).toBe(4_001);
});

it('SCALE/ignore-index an adversarial ignore file costs one match per fingerprint and path (old: about 21 minutes)', async () => temp('scale-ignore-', async dir => {
  const candidate = `0201036c6e6402${'ab'.repeat(20)}`;
  writeFileSync(join(dir, 'c.txt'), `X=${candidate}\n`.repeat(90_000));
  const hash = fp(candidate);
  const glob = `${'*a'.repeat(127)}Z`;
  writeFileSync(join(dir, '.macwardenignore'), `${`${hash} ${glob}\n`.repeat(1024)}`);
  const started = performance.now();
  const kept = await scan([dir]);
  expect(performance.now() - started).toBeLessThan(60_000);
  expect(kept.findings).toHaveLength(90_000);
  expect(kept.summary.ignored).toBe(0);
  writeFileSync(join(dir, '.macwardenignore'), `${`${hash} ${glob}\n`.repeat(1023)}${hash} c.txt\n`);
  const dropped = await scan([dir]);
  expect(dropped.findings).toEqual([]);
  expect(dropped.summary.ignored).toBe(90_000);
  expect(dropped.ignoredFingerprints).toEqual([hash]);
}), 180_000);

it('SCALE/cancellation an interrupt stops a directory walk promptly', async () => temp('scale-cancel-', async dir => {
  for (let i = 0; i < 400; i++) writeFileSync(join(dir, `f${i}.txt`), 'plain\n');
  const controller = new AbortController();
  let lstats = 0;
  const io = { ...fs, lstat: (async (...args: Parameters<typeof fs.lstat>) => {
    if (++lstats === 20) controller.abort();
    return fs.lstat(...args);
  }) as typeof fs.lstat };
  await expect(withCancellation(controller.signal, () => scan([dir], { fs: io }))).rejects.toBeInstanceOf(Cancelled);
  expect(lstats).toBeLessThan(100);
}));

function child(args: string[], options: { ipc?: boolean } = {}) {
  return spawn(process.execPath, options.ipc ? [resolve('test/helpers/scan-signal-child.mjs'), ...args] : [resolve('dist/bin.js'), ...args],
    { env: childEnvironment(), cwd: repo, windowsHide: true, stdio: options.ipc ? ['ignore', 'pipe', 'pipe', 'ipc'] : ['ignore', 'pipe', 'pipe'] });
}

it('SCALE/cancellation an interrupt during --git-history kills git and exits 6', async () => temp('scale-signal-', async dir => {
  // 200,000 blobs: several seconds of history work even on a fast machine, so the
  // interrupt below always lands while git is running.
  bulkHistory(dir, 200, 1000, (c, f) => `value ${c} ${f}`);
  const run = child(['scan', dir, '--git-history', '--json'], { ipc: true });
  let stdout = '';
  run.stdout!.on('data', value => { stdout += String(value); });
  run.stderr!.resume();
  let signalled = 0;
  run.on('message', message => {
    if ((message as { kind?: string }).kind !== 'ready') return;
    setTimeout(() => {
      signalled = performance.now();
      if (process.platform === 'win32') run.send({ kind: 'signal', signal: 'SIGTERM' });
      else run.kill('SIGTERM');
    }, 400);
  });
  const code = await new Promise<number | null>(done => run.once('close', done));
  expect(signalled).toBeGreaterThan(0);
  expect(performance.now() - signalled).toBeLessThan(15_000);
  expect(code).toBe(6);
  expect(JSON.parse(stdout)).toMatchObject({ ok: false, error: { code: 6, step: 'cancelled', message: 'interrupted' } });
}), 120_000);

it('SCALE/epipe a reader that stops early does not turn the exit status into an internal failure', async () => temp('scale-pipe-', async dir => {
  writeFileSync(join(dir, 'c.txt'), Array.from({ length: 20_000 }, (_, i) => `K${i}=0201036c6e6402${i.toString(16).padStart(40, '0')}\n`).join(''));
  const run = child(['scan', dir, '--fail-on', 'READ', '--json']);
  let stderr = '';
  run.stderr!.on('data', value => { stderr += String(value); });
  run.stdout!.once('data', () => run.stdout!.destroy());
  const code = await new Promise<number | null>(done => run.once('close', done));
  expect(stderr).not.toMatch(/internal/);
  expect(code).toBe(1);
}), 120_000);

it('SCALE/shallow-history a shallow clone fails closed unless --allow-shallow, which warns', async () => temp('scale-shallow-', async dir => {
  const origin = join(dir, 'origin');
  mkdirSync(origin);
  git(origin, 'init', '-q');
  writeFileSync(join(origin, 'old.env'), `TOKEN=${vector('default-admin').toString('hex')}\n`);
  git(origin, 'add', '-A'); git(origin, 'commit', '-q', '-m', 'leak');
  writeFileSync(join(origin, 'old.env'), 'TOKEN=\n');
  git(origin, 'add', '-A'); git(origin, 'commit', '-q', '-m', 'scrub');
  git(dir, 'clone', '-q', '--depth', '1', pathToFileURL(origin).href, 'shallow');
  const shallow = join(dir, 'shallow');
  const refused = spawnSync(process.execPath, [resolve('dist/bin.js'), 'scan', shallow, '--git-history', '--json'],
    { env: childEnvironment(), encoding: 'utf8', windowsHide: true });
  expect(refused.status).toBe(3);
  const failure = JSON.parse(refused.stdout);
  expect(failure.error).toMatchObject({ code: 3, step: 'git-history' });
  expect(failure.error.message).toMatch(/shallow.*fetch-depth: 0.*--allow-shallow/);
  expect(scanSchema(failure)).toBe(true);
  const allowed = spawnSync(process.execPath, [resolve('dist/bin.js'), 'scan', shallow, '--git-history', '--allow-shallow', '--json'],
    { env: childEnvironment(), encoding: 'utf8', windowsHide: true });
  expect(allowed.status).toBe(0);
  const document = JSON.parse(allowed.stdout);
  expect(scanSchema(document)).toBe(true);
  expect(document.warnings).toEqual(['shallow-history']);
  expect(document.result.summary.shallowHistory).toBe(true);
  // Only the fetched commit is visible: the deleted credential is not found, which is why the warning exists.
  expect(document.result.findings).toEqual([]);
  const text = spawnSync(process.execPath, [resolve('dist/bin.js'), 'scan', shallow, '--git-history', '--allow-shallow'],
    { env: childEnvironment(), encoding: 'utf8', windowsHide: true });
  expect(text.stderr).toMatch(/shallow/);
  const usage = spawnSync(process.execPath, [resolve('dist/bin.js'), 'scan', shallow, '--allow-shallow', '--json'],
    { env: childEnvironment(), encoding: 'utf8', windowsHide: true });
  expect(usage.status).toBe(2);
}), 120_000);

it('SCALE/git-history-compact a blob shared by paths, uses and path arguments is read once per use', async () => temp('scale-shared-', async dir => {
  git(dir, 'init', '-q');
  for (const sub of ['a', 'b', 'c']) mkdirSync(join(dir, sub));
  const hex = vector('default-admin').toString('hex');
  const files = [join(dir, 'a', 'token.txt'), join(dir, 'b', 'token.macaroon'), join(dir, 'c', 'copy.txt')];
  for (const file of files) writeFileSync(file, hex);
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'add');
  const added = git(dir, 'rev-parse', 'HEAD');
  for (const file of files) rmSync(file);
  git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'remove');
  const admin = fp(vector('default-admin'));
  const display = (path: string) => path.replaceAll('\\', '/');
  // One argument: the blob is used as text and as *.macaroon, and read once for both.
  const whole = await scan([dir], { gitHistory: true });
  // Text use: one finding at the first path with the copy in alsoAt. The *.macaroon use of
  // the same blob is a separate finding and is never folded into the text one.
  expect(whole.findings.map(finding => [finding.path, finding.kind, finding.fingerprint, finding.commit,
    (finding as { alsoAt?: unknown }).alsoAt])).toEqual([
    [display(files[0]), 'macaroon-hex', admin, added, { count: 1, paths: [display(files[2])] }],
    [display(files[1]), 'macaroon-file', admin, added, undefined]]);
  expect(whole.summary.blobsScanned).toBe(1);
  // Two arguments needing the same use: the second reuses the first outcome.
  const split = await scan([join(dir, 'a'), join(dir, 'c')], { gitHistory: true });
  expect(split.findings.map(finding => finding.path)).toEqual([display(files[0]), display(files[2])]);
  expect(split.summary.blobsScanned).toBe(1);
}), 60_000);

it('SCALE/git-history-compact a history of 60,000 added blobs is scanned with every entry accounted for', async () => temp('scale-bulk-', async dir => {
  const hex = vector('default-readonly').toString('hex');
  bulkHistory(dir, 60, 1000, (c, f) => c === 3 && f === 500 ? `TOKEN=${hex}` : `value ${c} ${f}`);
  const result = await scan([dir], { gitHistory: true });
  // 60 commits x 1,000 files, each with new content: 60,000 distinct blobs.
  expect(result.summary.blobsScanned).toBe(60_000);
  expect(result.findings).toEqual([expect.objectContaining({ kind: 'macaroon-hex', path: expect.stringMatching(/d0\/f500\.txt$/),
    fingerprint: fp(vector('default-readonly')), line: 1, column: 7 })]);
}), 120_000);
