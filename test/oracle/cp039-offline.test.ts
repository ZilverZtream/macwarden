import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { it, expect, vi } from 'vitest';
import { captureMain } from '../support/capture.js';
import { fingerprint, scratch, vector } from '../support/cp039-audit.js';

const attempts = vi.hoisted(() => [] as string[]);
const blocked = (name: string) => () => { attempts.push(name); throw new Error('Offline network attempt'); };
vi.mock('node:https', async load => {
  const actual = await load<typeof import('node:https')>();
  const request = () => { attempts.push('https'); throw new Error('Offline network attempt'); };
  return { ...actual, request, get: request, default: { ...actual, request, get: request } };
});
vi.mock('node:http', async load => {
  const actual = await load<typeof import('node:http')>();
  const request = () => { attempts.push('http'); throw new Error('Offline network attempt'); };
  return { ...actual, request, get: request, default: { ...actual, request, get: request } };
});
vi.mock('node:net', async load => {
  const actual = await load<typeof import('node:net')>();
  const connect = () => { attempts.push('net'); throw new Error('Offline network attempt'); };
  return { ...actual, connect, createConnection: connect, default: { ...actual, connect, createConnection: connect } };
});
vi.mock('node:dns', async load => {
  const actual = await load<typeof import('node:dns')>();
  const lookup = () => { attempts.push('dns'); throw new Error('Offline network attempt'); };
  return { ...actual, lookup, resolve: lookup, default: { ...actual, lookup, resolve: lookup } };
});
vi.mock('node:tls', async load => {
  const actual = await load<typeof import('node:tls')>();
  const connect = () => { attempts.push('tls'); throw new Error('Offline network attempt'); };
  return { ...actual, connect, default: { ...actual, connect } };
});
vi.mock('node:http2', async load => {
  const actual = await load<typeof import('node:http2')>();
  const connect = () => { attempts.push('http2'); throw new Error('Offline network attempt'); };
  return { ...actual, connect, default: { ...actual, connect } };
});
vi.mock('node:dgram', async load => {
  const actual = await load<typeof import('node:dgram')>();
  const createSocket = () => { attempts.push('dgram'); throw new Error('Offline network attempt'); };
  return { ...actual, createSocket, default: { ...actual, createSocket } };
});

it('CP-039/offline-readonly inspect and scan preserve the independent file manifest with every network attempt trapped',
  async () => scratch(async dir => {
    for (const name of ['fetch', 'WebSocket', 'EventSource']) vi.stubGlobal(name, blocked(name));
    try {
      const v = vector('default-readonly'), file = join(dir, 'fixture.macaroon');
      writeFileSync(file, v.bytes, { mode: 0o400 });
      const manifest = () => readdirSync(dir).map(name => {
        const path = join(dir, name), stat = statSync(path);
        return { name, hash: fingerprint(readFileSync(path)), size: stat.size, mtime: stat.mtimeMs, mode: stat.mode };
      });
      const before = manifest();
      const { main } = await import('../../src/cli.js');
      for (const command of ['inspect', 'scan']) {
        const actual = await captureMain(main, [command, file, '--json']);
        expect(actual.code, command).toBe(0); expect(actual.stderr).toBe('');
        const document = JSON.parse(actual.stdout);
        expect(document).toMatchObject({ schema: 1, command, ok: true, error: null });
        if (command === 'inspect') expect(document.result).toMatchObject({ fingerprint: v.fingerprint, grade: v.expectedGrade });
        else expect(document.result).toMatchObject({ findings: [{ fingerprint: v.fingerprint, grade: v.expectedGrade }],
          summary: { filesScanned: 1, findings: 1, distinct: 1 } });
      }
      expect(attempts).toEqual([]); expect(manifest()).toEqual(before);
    } finally { vi.unstubAllGlobals(); }
  }));
