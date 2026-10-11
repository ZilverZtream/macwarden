// Windows variant (scripts/platform-variants.mjs) of OUT-REGISTRY/case-rule in
// test/out-registry-collision.test.ts: on a file system that folds case, --out naming the
// registry in another letter case is the registry itself and is refused at B4 before any lock,
// file or LND call. The rule (folded on Windows and macOS, exact elsewhere) is checked on every
// platform in the counterpart; here a real bake runs on a case-folding file system.
import { mkdtempSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run as bake } from '../src/commands/bake/index.js';
import { Secret } from '../src/secret.js';
import { directory, fixture } from './helpers/cp025-bake-support.mjs';

it('OUT-REGISTRY/case-windows bake refuses --out naming the registry in another letter case', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'out-registry-'));
  const f = fixture(dir, Secret);
  const args = [...f.args]; args[args.indexOf('--out') + 1] = join(dir, 'REGISTRY.JSON');
  const result = await bake(args, f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'B4' }); expect(f.state.calls).toEqual([]);
  expect(readdirSync(dir).filter(name => name.toLowerCase().startsWith('registry.json'))).toEqual([]);
});
