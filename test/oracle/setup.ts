import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { basename, resolve } from 'node:path';
import { afterAll, beforeAll, beforeEach } from 'vitest';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { clearFixtureTurn, prepareFixtureTurn } from '../helpers/fixture-copies.js';
import { createFixture } from '../fixture/fixture.mjs';
import { createPrivateDirectory } from '../../scripts/private-scratch.mjs';

const compose = fixtureTopology().composeArgs;
function docker(args: string[], binary = false): string | Buffer {
  const result = spawnSync('docker', [...compose, ...args], { cwd: resolve(), encoding: binary ? null : 'utf8',
    env: childEnvironment(), timeout: 30000, maxBuffer: 2_000_000 });
  if (result.error || result.status !== 0) throw new FixtureInvalidError('Pinned regtest fixture is unavailable; run npm run fixture:up');
  return result.stdout;
}
function fixtureState(): void {
  const info = JSON.parse(String(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'getinfo']))) as {
    chains?: { network?: string }[]; version?: string;
  };
  if (info.chains?.[0]?.network !== 'regtest' || !info.version?.startsWith('0.21.4-beta'))
    throw new FixtureInvalidError('Fixture must be LND 0.21.4-beta on regtest');
}
function cleanRootKeys(): void {
  fixtureState();
  const value = JSON.parse(String(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'listmacaroonids']))) as { root_key_ids?: unknown };
  if (!Array.isArray(value.root_key_ids) || value.root_key_ids.some(id => !/^(0|[1-9][0-9]*)$/.test(String(id))))
    throw new FixtureInvalidError('Fixture root key IDs are invalid');
  for (const id of value.root_key_ids.map(String).filter(id => id !== '0')) {
    const result = JSON.parse(String(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'deletemacaroonid', id]))) as { deleted?: boolean };
    if (result.deleted !== true) throw new FixtureInvalidError('Fixture root key cleanup failed');
  }
  const after = JSON.parse(String(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'listmacaroonids']))) as { root_key_ids?: unknown };
  if (JSON.stringify(after.root_key_ids) !== '["0"]') throw new FixtureInvalidError('Fixture has leftover root key IDs');
}
function freshFixture(): void {
  fixtureState();
  const value = JSON.parse(String(docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'listmacaroonids']))) as { root_key_ids?: unknown };
  if (JSON.stringify(value.root_key_ids) !== '["0"]') throw new FixtureInvalidError('Fixture has leftover root key IDs');
}
async function prepare(validate: () => void): Promise<void> {
  await prepareFixtureTurn(process.env, validate, name => {
    const remote = name === 'tls.cert' ? '/root/.lnd/tls.cert' : '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon';
    return docker(['exec', '-T', 'lnd', 'cat', remote], true) as Buffer;
  });
}
// Configuration must set fileParallelism:false, maxWorkers:1 and sequence.concurrent:false.
// Root-key regeneration changes the wallet password and recreates the container.
// Cleaning IDs cannot restore that state or the gRPC mapping. The caller owns
// fixture:up/down for the suite; only these mutators need a disposable reset
// before the next file. Ordinary files validate and retain the caller's fixture.
const resetFiles = new Set(['cp015-facts.test.ts', 'cp020-inventory.test.ts', 'cp033-guide.test.ts']);
// beforeAll guide/BTCPay scenarios intentionally share their baked state across
// their assertions; all other scenarios clean nonzero IDs before each test.
let ready = false;
let fixture: ReturnType<typeof createFixture> | undefined;
let startup: Promise<void> | undefined;
let skipSharedFixture = false;
// eslint-disable-next-line no-empty-pattern -- Vitest 5 requires destructured fixture context; suite is the second argument.
beforeAll(({}, suite) => {
  // CP-050 proves ownership using two controllers and performs its own pinned
  // network/version/freshness validation. It never borrows the caller's fixture.
  // CP-044's offline reference requires no fixture.
  skipSharedFixture = ['cp050-policy.test.ts', 'cp044-authority.test.ts', 'cp047-claim.test.ts', 'cp048-separators.test.ts', 'cp049-artifact.test.ts', 'cp049-evidence.test.ts'].includes(basename(suite.file.filepath));
  if (skipSharedFixture) return;
  startup = (async () => {
    const root = process.env.MACWARDEN_FIXTURE_COPY_ROOT;
    if (!root) throw new FixtureInvalidError('Bootstrap-owned fixture copy root is required');
    if (resetFiles.has(basename(suite.file.filepath))) {
      // A private reset controller also restores state after a failed mutator
      // hook. Creating it does not start or stop the caller's fixture.
      fixture = createFixture({ tempBase: await createPrivateDirectory(root, 'control-'),
        docker: (args, options) => spawnSync('docker', [...compose, ...args], {
          ...options, encoding: options.encoding === null ? null : 'utf8', cwd: resolve(), env: childEnvironment(),
        }) });
    }
    await prepare(freshFixture);
    ready = true;
  })();
  // Use the configured oracle hook budget for startup and validation.
  return startup;
});
beforeEach(async ({ task }) => {
  if (skipSharedFixture) return;
  const file = task.file.filepath;
  await prepare(/cp033-guide|cp034-btcpay/.test(file) ? fixtureState : cleanRootKeys);
}, 60000);
afterAll(async () => {
  if (skipSharedFixture) return;
  try {
    // A timed-out hook may still be starting or validating its fixture.
    // Its rejection remains the setup failure; teardown waits for settlement.
    await startup?.catch(() => {});
    if (ready) {
      spawnSync('docker', [...compose, 'unpause', 'lnd'], { cwd: resolve(), env: childEnvironment(), timeout: 30000 });
      cleanRootKeys();
    }
  } finally {
    try {
      if (fixture) {
        // up() replaces disposable volumes and restores both REST and gRPC.
        // Keep the restored fixture running for subsequent files and the caller.
        await fixture.up();
        await prepare(freshFixture);
      }
    }
    finally { clearFixtureTurn(process.env); }
  }
});
