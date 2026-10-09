import { fixtureTopology } from './topology.mjs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFixture } from './fixture.mjs';

export const cp024Compose = fixtureTopology().composeArgs;
export function createCp024Fixture() {
  return createFixture({
    docker: (args, options) => spawnSync('docker', [...cp024Compose, ...args], options) });
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixture = createCp024Fixture();
  try {
    if (process.argv[2] === 'up') await fixture.up();
    else if (process.argv[2] === 'down') fixture.down();
    else throw new Error('Usage: cp024-fixture.mjs up|down');
  } catch (error) {
    process.stderr.write(`${error.name}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
