import { afterEach, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createFixture } from './fixture/fixture.mjs';

const base = resolve(process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp'));
const roots: string[] = [];

function temp(): string {
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, 'cp004-timeout-'));
  roots.push(root);
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    const target = resolve(root);
    if (!target.startsWith(base + '\\') && !target.startsWith(base + '/')) throw new Error('Unsafe test temp path');
    rmSync(target, { recursive: true, force: true });
  }
});

// The stalled response is aborted by the fixture's own 80 ms deadline. The bound is measured from
// the first Docker call (after the private-directory check, which spawns PowerShell on Windows and
// can take seconds on a loaded runner) to the abort: at least most of the deadline (the abort waited
// for its timer) and far below a stall. The test timeout only guards against a hang.
const STALL_CEILING_MS = 10_000;
it('CP-004/fixture-pinned stalled getinfo response is aborted and the owned fixture is cleaned', async () => {
  const root = temp();
  const fixtureDir = join(root, 'macwarden-fixture');
  const calls: string[] = [];
  let destroyed = false;
  let opened = false;
  let firstCall: number | undefined;
  let destroyedAt: number | undefined;
  const fixture = createFixture({
    tempBase: root,
    timeout: 80,
    docker: (args: string[], options: { timeout: number }) => {
      firstCall ??= performance.now();
      calls.push(args[0]);
      expect(options.timeout).toBeGreaterThan(0);
      if (args[0] === 'exec') return { status: 0, stdout: Buffer.alloc(0) };
      return { status: 0, stdout: '' };
    },
    httpsRequest: (_options: unknown, response: (value: EventEmitter) => void) => {
      const req = new EventEmitter() as EventEmitter & { end: () => void; destroy: () => void };
      req.end = () => {
        opened = true;
        const stream = new EventEmitter() as EventEmitter & { statusCode: number };
        stream.statusCode = 200;
        response(stream);
      };
      req.destroy = () => { destroyed = true; destroyedAt = performance.now(); };
      return req;
    },
  });
  await expect(fixture.up()).rejects.toThrow(/timed out/);
  expect(opened).toBe(true);
  expect(destroyed).toBe(true);
  expect(destroyedAt! - firstCall!).toBeGreaterThanOrEqual(50);
  expect(destroyedAt! - firstCall!).toBeLessThan(STALL_CEILING_MS);
  expect(calls.filter(call => call === 'down')).toHaveLength(2);
  expect(existsSync(fixtureDir)).toBe(false);
}, 30_000);

it('CP-004/fixture-pinned Docker startup and copies share the deadline and timeout cleanup removes copied files', async () => {
  const root = temp();
  const fixtureDir = join(root, 'macwarden-fixture');
  const calls: string[] = [];
  const budgets: number[] = [];
  let now = 0;
  const fixture = createFixture({
    tempBase: root,
    timeout: 120,
    clock: () => now,
    // This deadline control uses only dummy copies beneath caller-protected
    // scratch. Real ACL provisioning/refusal has separate filesystem controls.
    privateDirectories: {
      assert: async path => { expect(statSync(path).isDirectory()).toBe(true); },
      create: async (parent, prefix) => mkdtempSync(join(parent, prefix)),
    },
    docker: (args: string[], options: { timeout: number }) => {
      calls.push(args[0]);
      budgets.push(options.timeout);
      if (args[0] === 'exec' && args.includes('listmacaroonids')) { now += 10; return { status: 0, stdout: '{"root_key_ids":["0"]}' }; }
      if (args[0] === 'exec') { now += 10; return { status: 0, stdout: Buffer.alloc(0) }; }
      if (args[0] === 'cp') {
        expect(statSync(fixtureDir).isDirectory()).toBe(true);
        writeFileSync(args[2], Buffer.alloc(0));
        now += args[2].endsWith('admin.macaroon') ? 60 : 10;
        return { status: 0, stdout: '' };
      }
      now += 10;
      return { status: 0, stdout: '' };
    },
    httpsRequest: (_options: unknown, response: (value: EventEmitter) => void) => {
      const req = new EventEmitter() as EventEmitter & { end: () => void };
      req.end = () => {
        const stream = new EventEmitter() as EventEmitter & { statusCode: number };
        stream.statusCode = 200;
        response(stream);
        stream.emit('data', Buffer.from(JSON.stringify({ chains: [{ network: 'regtest' }], version: '0.21.4-beta' })));
        stream.emit('end');
      };
      return req;
    },
  });
  await expect(fixture.up()).rejects.toThrow(/startup timed out/);
  expect(calls).toEqual(['down', 'up', 'exec', 'exec', 'exec', 'cp', 'cp', 'down']);
  expect(budgets.slice(0, -1)).toEqual([120, 110, 100, 90, 80, 70, 60]);
  expect(existsSync(fixtureDir)).toBe(false);
});

it('CP-004/fixture-pinned a stalled Docker up call reaches cleanup without polling getinfo', async () => {
  const root = temp();
  const calls: string[] = [];
  const budgets: number[] = [];
  let now = 0;
  const fixture = createFixture({
    tempBase: root,
    timeout: 120,
    clock: () => now,
    docker: (args: string[], options: { timeout: number }) => {
      calls.push(args[0]);
      budgets.push(options.timeout);
      now += args[0] === 'up' ? 90 : 30;
      return { status: 0, stdout: '' };
    },
    httpsRequest: () => { throw new Error('getinfo must not be called after startup timeout'); },
  });
  await expect(fixture.up()).rejects.toThrow(/startup timed out/);
  expect(calls).toEqual(['down', 'up', 'down']);
  expect(budgets).toEqual([120, 90, 30_000]);
  expect(existsSync(join(root, 'macwarden-fixture'))).toBe(false);
});
