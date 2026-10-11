// Pre-1.4 audit (READCMD): respond lists each root key ID once, and respond and verify read
// the TLS certificate by the resolved path they checked.
import { copyFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';
import { run as respond } from '../src/commands/respond.js';
import { run as verify } from '../src/commands/verify.js';
import type { RespondResult } from '../src/command-result.js';
import { entry, fixture, oldId, ownId } from './helpers/cp038-online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

const unknownId = 777777n, revokedId = 4294967999n;

it('READCMD-09 respond lists a root key ID LND returns twice only once', async () => {
  const f = fixture();
  f.save([f.old, { ...entry(revokedId, 'Gone'), label: null, status: 'revoked', revokedAt: '2026-10-05T12:00:00Z', revokeEvidence: 'by-id-only' }]);
  f.lnd.ids = [0n, ownId, oldId, unknownId, unknownId, revokedId, revokedId];
  const output = await respond(['--dry-run', ...f.flags], f.deps);
  expectSchemaValid(output);
  const result = output.result as RespondResult;
  expect(result.unknown.rootKeyIds).toEqual([String(unknownId)]);
  expect(result.revokedButPresent.rootKeyIds).toEqual([String(revokedId)]);
});

/**
 * A file system whose TLS certificate link is swapped after the first lookup: the first
 * realpath gives the checked file, later ones another file. Records every path opened.
 */
function swappingFs(link: string, checked: string, swapped: string) {
  const opened: string[] = [];
  let lookups = 0;
  const io = { ...fs,
    realpath: (async (path: string) => path === link ? (lookups++ === 0 ? checked : swapped) : fs.realpath(path)) as typeof fs.realpath,
    open: (async (path: string, ...rest: unknown[]) => { opened.push(String(path));
      return (fs.open as (...args: unknown[]) => Promise<fs.FileHandle>)(path, ...rest); }) as typeof fs.open };
  return { io, opened };
}

it('READCMD-14 respond and verify read the certificate path they resolved and checked', async () => {
  const f = fixture();
  const checked = join(f.dir, 'checked.cert'), swapped = join(f.dir, 'swapped.cert'), link = join(f.dir, 'tls.cert');
  copyFileSync(resolve('test/fixture/wrong-tls.cert'), checked);
  copyFileSync(resolve('test/fixture/wrong-tls.cert'), swapped);
  const flags = f.flags.map(value => value === resolve('test/fixture/wrong-tls.cert') ? link : value);
  const forRespond = swappingFs(link, checked, swapped);
  await respond(['--dry-run', ...flags], { ...f.deps, fs: forRespond.io });
  expect(forRespond.opened).toContain(checked);
  expect(forRespond.opened).not.toContain(swapped);
  f.save([f.old]);
  const forVerify = swappingFs(link, checked, swapped);
  await verify([f.old.outPath!, ...flags], { lnd: f.lnd, fs: forVerify.io, env: {}, clock: f.deps.clock,
    stdin: Object.assign(Readable.from([]), { isTTY: true }) });
  expect(forVerify.opened).toContain(checked);
  expect(forVerify.opened).not.toContain(swapped);
});
