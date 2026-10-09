import { fixtureTopology } from './topology.mjs';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, renameSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { request } from 'node:https';
import { fileURLToPath } from 'node:url';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { assertPrivateDirectory, createPrivateDirectory } from '../../scripts/private-scratch.mjs';

// The full oracle suite includes the native HtlcInterceptor reference probe.
// Every fresh fixture must expose its pinned gRPC listener as well as REST.
const startupTimeout = 120_000;

/**
 * @param {{docker?: (args:string[], options:{encoding:string|null,timeout:number,maxBuffer:number}) => {status:number|null,stdout:string|Buffer},
 * httpsRequest?: (options:import('node:https').RequestOptions, response:(stream:import('node:events').EventEmitter & {statusCode?:number})=>void)=>import('node:events').EventEmitter & {end():void,destroy?():void},
 * clock?:()=>number,sleep?:(ms:number)=>Promise<void>,timeout?:number,tempBase?:string,
 * env?:Record<string,string|undefined>,
 * privateDirectories?:{assert:(path:string)=>Promise<void>,create:(base:string,prefix:string)=>Promise<string>}}} [options]
 */
export function createFixture({
  env = process.env,
  docker = (args, options) => spawnSync('docker', [...fixtureTopology(env).composeArgs, ...args], options),
  httpsRequest = (options, response) => request(options, response),
  clock = () => Date.now(),
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  timeout = startupTimeout,
  tempBase = resolve(`test/.tmp/fixture-control${fixtureTopology(env).project ? `-${fixtureTopology(env).project}` : ''}`),
  privateDirectories = { assert: assertPrivateDirectory, create: createPrivateDirectory },
} = {}) {
  const topology = fixtureTopology(env);
  const fixtureDir = resolve(tempBase, 'macwarden-fixture');

  async function validateRoots(createBase) {
    const base = resolve(tempBase);
    if (!existsSync(base) && createBase) {
      mkdirSync(dirname(base), { recursive: true, mode: 0o700 });
      renameSync(await privateDirectories.create(dirname(base), 'fixture-control-'), base);
    }
    if (existsSync(base)) await privateDirectories.assert(base);
    if (existsSync(fixtureDir)) await privateDirectories.assert(fixtureDir);
  }

  function run(args, binary = false, deadline) {
    const remaining = deadline === undefined ? 30_000 : deadline - clock();
    if (remaining <= 0) throw new FixtureInvalidError('Fixture startup timed out');
    const result = docker(args, { encoding: binary ? null : 'utf8', timeout: Math.min(30_000, remaining), maxBuffer: 2_000_000 });
    if (deadline !== undefined && clock() >= deadline) throw new FixtureInvalidError('Fixture startup timed out');
    return result;
  }

  function cleanFixtureDir() {
    if (fixtureDir !== join(resolve(tempBase), 'macwarden-fixture')) throw new Error('Invalid fixture directory');
    if (existsSync(fixtureDir)) rmSync(fixtureDir, { recursive: true, force: true });
  }

  function down(deadline) {
    let result;
    try { result = run(['down', '-v', '--remove-orphans'], false, deadline); }
    finally { cleanFixtureDir(); }
    if (result.status !== 0) throw new Error('Docker fixture teardown failed');
  }

  async function getInfo(deadline) {
    const cert = run(['exec', '-T', 'lnd', 'cat', '/root/.lnd/tls.cert'], true, deadline);
    const macaroon = run(['exec', '-T', 'lnd', 'cat', '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon'], true, deadline);
    if (cert.status !== 0 || macaroon.status !== 0) return null;
    const remaining = deadline - clock();
    if (remaining <= 0) throw new FixtureInvalidError('Fixture startup timed out');
    return await new Promise(resolveInfo => {
      let settled = false;
      let timer;
      const finish = value => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolveInfo(value);
      };
      const req = httpsRequest({ hostname: 'localhost', port: topology.restPort, path: '/v1/getinfo', ca: cert.stdout,
        headers: { 'Grpc-Metadata-macaroon': macaroon.stdout.toString('hex') } }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('error', () => finish(null));
        response.on('end', () => {
          if (response.statusCode !== 200) { finish(null); return; }
          try { finish(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { finish(null); }
        });
      });
      req.on('error', () => finish(null));
      timer = setTimeout(() => { req.destroy?.(); finish(null); }, remaining);
      req.end();
    });
  }

  function checkRootKeyIds(deadline) {
    const result = run(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'listmacaroonids'], false, deadline);
    if (result.status !== 0) throw new FixtureInvalidError('Fixture root key IDs could not be checked');
    let ids;
    try { ids = JSON.parse(result.stdout).root_key_ids; } catch { throw new FixtureInvalidError('Fixture root key IDs are invalid'); }
    if (!Array.isArray(ids) || ids.some(id => String(id) !== '0')) throw new FixtureInvalidError('Fixture has leftover root key IDs');
  }

  async function up() {
    // Reject unsafe caller paths before teardown can remove them or Docker runs.
    await validateRoots(true);
    const deadline = clock() + timeout;
    try {
      down(deadline);
      const started = run(['up', '-d'], false, deadline);
      if (started.status !== 0) throw new FixtureInvalidError('Docker fixture startup failed');
      while (clock() < deadline) {
        const info = await getInfo(deadline);
        if (info) {
          if (info.chains?.[0]?.network !== 'regtest' || !info.version?.startsWith('0.21.4-beta')) {
            throw new FixtureInvalidError('Fixture must be LND 0.21.4-beta on regtest');
          }
          checkRootKeyIds(deadline);
          renameSync(await privateDirectories.create(resolve(tempBase), 'fixture-copies-'), fixtureDir);
          await privateDirectories.assert(fixtureDir);
          for (const name of ['tls.cert', 'admin.macaroon']) {
            const source = name === 'tls.cert' ? '/root/.lnd/tls.cert' : '/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon';
            const copied = run(['cp', `lnd:${source}`, join(fixtureDir, name)], false, deadline);
            if (copied.status !== 0) throw new FixtureInvalidError(`Fixture could not copy ${name}`);
          }
          process.stdout.write(`Fixture ready: ${info.chains[0].network}, ${info.version}\n`);
          return;
        }
        await sleep(Math.min(2000, Math.max(0, deadline - clock())));
      }
      throw new FixtureInvalidError('Fixture getinfo timed out');
    } catch (error) {
      try { down(); } catch { /* Best effort cleanup. */ }
      if (error instanceof Error && error.message === 'Docker fixture teardown failed')
        throw new FixtureInvalidError('Pinned regtest fixture is unavailable during setup');
      throw error;
    }
  }

  return { up, down: async () => { await validateRoots(false); down(); } };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixture = createFixture();
  try {
    if (process.argv[2] === 'up') await fixture.up();
    else if (process.argv[2] === 'down') await fixture.down();
    else throw new Error('Usage: fixture.mjs up|down');
  } catch (error) {
    process.stderr.write(`${error.name}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
