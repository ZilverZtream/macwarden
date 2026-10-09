import { fixtureTopology } from '../fixture/topology.mjs';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../../src/secret.js';
import { render } from '../../src/output/index.js';
import { childEnvironment } from '../helpers/environment.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { builtInspect, fingerprint, independentCaveat, leakForms, leakStatus, noEcho, peerForms, register, repo,
  scratch, sentinel, sentinelList, variants, vector } from '../support/cp041-controls.js';
import { findLeaks } from '../helpers/leak-check.js';

it('CP-041/canonical-fingerprint-independent independently hashes vector trailing variants and a genuine caveat', () => scratch(dir => {
  const v = vector(); expect(fingerprint(v.canonical)).toBe(v.fingerprint);
  for (const [index, bytes] of [...variants(), independentCaveat().bytes].entries()) {
    register(bytes); const path = join(dir, `reference-${index}.macaroon`); writeFileSync(path, bytes);
    const expected = index === 3 ? independentCaveat().fingerprint : v.fingerprint;
    expect(new Secret(bytes).fingerprint).toBe(expected); expect(builtInspect(path).result.fingerprint).toBe(expected);
  }
}));
it('CP-041/canonical-printmacaroon-live canonical and trailing inspect facts match pinned live lncli', () => scratch(dir => {
  const docker = (args: string[]) => spawnSync('docker', [...fixtureTopology().composeArgs, ...args],
    { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 30_000 });
  const lncli = (args: string[]) => {
    const run = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
    if (run.status !== 0) throw new FixtureInvalidError('Pinned live lncli unavailable');
    try { return JSON.parse(run.stdout) as { chains?: { network: string }[]; version?: string; root_key_ids?: string[];
      root_key_id?: string; permissions?: string[]; caveats?: string[] | null }; }
    catch { throw new FixtureInvalidError('Pinned live lncli emitted invalid JSON'); }
  };
  const info = lncli(['getinfo']);
  if (info.chains?.[0]?.network !== 'regtest' || !info.version?.startsWith('0.21.4-beta') ||
    JSON.stringify(lncli(['listmacaroonids']).root_key_ids) !== '["0"]') throw new FixtureInvalidError('Fresh pinned regtest required');
  const v = vector();
  for (const [index, bytes] of [...variants(), independentCaveat().bytes].entries()) {
    register(bytes); const path = join(dir, `live-${index}.macaroon`), remote = `/tmp/cp041-${process.pid}-${index}.macaroon`;
    writeFileSync(path, bytes);
    if (docker(['cp', path, `lnd:${remote}`]).status !== 0) throw new FixtureInvalidError('Fixture vector transfer unavailable');
    try {
      const live = lncli(['printmacaroon', `--macaroon_file=${remote}`]), actual = builtInspect(path).result;
      expect(actual.rootKeyId).toBe(live.root_key_id); expect(actual.permissions).toEqual(live.permissions);
      expect(actual.permissions).toEqual(v.printed.permissions);
      expect(actual.caveats.map(c => c.type === 'unknown' ? c.value : `${c.type} ${c.value}`)).toEqual(live.caveats ?? []);
      expect(actual.fingerprint).toBe(index === 3 ? independentCaveat().fingerprint : fingerprint(v.canonical));
      expect(actual.warnings.includes('trailing-bytes')).toBe(index === 1 || index === 2);
    } finally { docker(['exec', '-T', 'lnd', 'rm', '-f', remote]); }
  }
}));
it('CP-041/encoding-ground-truth independent controls suppress renderer echoes and detect output and scratch leaks', () => scratch(dir => {
  const bytes = sentinel(), path = join(dir, 'independent-capture.txt');
  for (const form of leakForms) {
    writeFileSync(path, form.encode(bytes));
    expect.soft(findLeaks({ sentinels: sentinelList, root: repo, paths: [path] }) !== null, `${form.name} independent file control`).toBe(true);
  }
  for (const form of peerForms) {
    const message = `safe-left ${String(form.encode(bytes))} safe-right`;
    expect.soft(findLeaks({ sentinels: sentinelList, root: repo, commandOutput: message }) !== null, `${form.name} output control`).toBe(true);
    const rendered = render({ schema: 1, command: 'inventory', ok: false, warnings: [], result: null,
      error: { code: 5, step: 'N4', message } }, 'json');
    noEcho(rendered, bytes); expect(rendered.includes('[redacted]')).toBe(true);
  }
}));
it('CP-041/leak-check standing leak CLI requires nonempty sources and exact product-output exclusions', () => scratch(dir => {
  mkdirSync(join(dir, 'runtime'));
  const capture = join(dir, 'capture.txt'), product = join(dir, 'issued.macaroon');
  writeFileSync(capture, `safe-left [redacted ${fingerprint(sentinel())}] safe-right`);
  writeFileSync(product, sentinel()); writeFileSync(join(dir, 'declared-out.txt'), product + '\n');
  expect(leakStatus(dir, dir), 'clean redacted output and exact declared output').toBe(0);
  writeFileSync(join(dir, 'issued.macaroon.log'), String(peerForms[0].encode(sentinel())));
  expect(leakStatus(dir, dir), 'neighbor is not excluded by product output name').toBe(1);
}));
