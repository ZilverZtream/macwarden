import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { scenario, ids, probe } from '../helpers/cp038-live.js';
import { childEnvironment } from '../helpers/environment.js';
import { findLeaks } from '../helpers/leak-check.js';
import { root } from '../helpers/cp038-online.js';

it.each(['bake', 'stage', 'revoke', 'finish'] as const)(
  'CP-040/candidate-reference-state %s dry-run leaves independent root-key and acceptance state unchanged', async mode => scenario(async f => {
    if (mode === 'finish') f.save([f.old, f.next]);
    const beforeIds = ids(), beforeRegistry = readFileSync(f.registry);
    const old = f.old.outPath, next = f.next.outPath;
    if (!old || !next) throw new Error('Live scenario must have known credential files');
    expect([probe(old), probe(next)]).toEqual(['accepted', 'accepted']);
    const args = mode === 'bake' ? ['bake', '--label', 'Bob', '--preset', 'invoice-only', '--out', f.out]
      : mode === 'stage' ? ['rotate', 'Alice', '--out', f.out]
      : mode === 'finish' ? ['rotate', 'Alice', '--finish'] : ['revoke', 'Alice'];
    const actual = spawnSync(process.execPath, [resolve('dist/bin.js'), ...args, ...f.flags, '--dry-run', '--json'],
      { encoding: 'utf8', timeout: 20000, env: childEnvironment() });
    expect(actual.error).toBeUndefined(); expect(actual.status).toBe(0);
    expect(JSON.parse(actual.stdout)).toMatchObject({ok:true,error:null,result:{dryRun:true}});
    expect(ids()).toEqual(beforeIds); expect(readFileSync(f.registry).equals(beforeRegistry)).toBe(true);
    expect([probe(old), probe(next)]).toEqual(['accepted', 'accepted']);
    expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry+'.lock')).toBe(false);
  }), 60000);

it('CP-040/leak-check live command captures and registry retain fingerprints without credential disclosures', async () => scenario(async f => {
  const actual = spawnSync(process.execPath, [resolve('dist/bin.js'), 'inventory', ...f.flags, '--verify', '--json'],
    { encoding: 'utf8', timeout: 20000, env: childEnvironment() });
  expect(actual.error).toBeUndefined(); expect(actual.status).toBe(0);
  expect(findLeaks({root:resolve(),sentinels:resolve('test/sentinels.json'),sentinelDir:root('MACWARDEN_SENTINEL_DIR'),
    testTmp:root('MACWARDEN_TEST_TMP'),commandOutput:actual.stdout+actual.stderr,paths:[f.registry]})).toBeNull();
}), 60000);
