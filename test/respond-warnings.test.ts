import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { run as respond } from '../src/commands/respond.js';
import type { RespondResult } from '../src/command-result.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { declareStagedFiles, declareStaging, entry, fixture, oldId, ownId } from './helpers/cp038-online.js';

// Audit 1.3.2: respond stages through rotate, so rotate's invocation warnings are respond's too.
// Only a Windows volume without permissions (FAT, exFAT) makes the reservation report acl-best-effort.
vi.mock('../src/commands/bake/write-out.js', async original => {
  const actual = await original<typeof import('../src/commands/bake/write-out.js')>();
  return { ...actual, reserveOut: async (...args: Parameters<typeof actual.reserveOut>) =>
    ({ ...(await actual.reserveOut(...args)), aclWarning: true }) };
});

afterEach(() => { declareStagedFiles(); });

it('RESPOND/audit-1.3.2 rotate\'s acl-best-effort warning reaches the respond result once for the whole batch', async () => {
  const f = fixture();
  const bobId = 4294967400n;
  f.save([f.old, entry(bobId, 'Bob')]);
  f.lnd.ids = [0n, ownId, oldId, bobId];
  const outDir = declareStaging(join(f.dir, 'replacements'));
  const output = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  expectSchemaValid(output);
  expect(output.error).toBeNull();
  expect((output.result as RespondResult).items.map(item => item.status)).toEqual(['staged', 'staged']);
  const codes = output.warnings.map(warning => typeof warning === 'string' ? warning : warning.code);
  expect(codes.filter(code => code === 'acl-best-effort')).toHaveLength(1);
});
