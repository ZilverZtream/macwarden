// Windows variant (scripts/platform-variants.mjs) of ENV-CASE/portable in test/cli-runtime.test.ts:
// Windows environment names are case-insensitive, so Node applies node_options and node_debug
// spelled in any case. The built CLI must refuse them like NODE_OPTIONS and NODE_DEBUG (audit 1.4.0).
// It spawns dist/bin.js and so checks the current build.
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';

it.each([['node_options', '--no-deprecation'], ['Node_Options', '--no-deprecation'], ['node_debug', 'tls']])(
  'ENV-CASE/windows built inspect refuses %s=%s', (name, value) => {
    const env = childEnvironment();
    delete env.NODE_OPTIONS; delete env.NODE_DEBUG;
    env[name] = value;
    const child = spawnSync(process.execPath, [resolve('dist/bin.js'), 'inspect', resolve('test/vectors/default-readonly.macaroon'), '--json'],
      { env, encoding: 'utf8', timeout: 30_000 });
    expect(child.error).toBeUndefined();
    expect(child.status, child.stdout + child.stderr).toBe(2);
    expect(JSON.parse(child.stdout)).toMatchObject({ command: 'inspect', ok: false, error: { code: 2, message: 'unsafe Node diagnostic settings' } });
  });
