import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';

// Refusals must name the flag and the rule so an operator can fix the command,
// and must never repeat the supplied value (SAFE-01).
const repo = resolve();
const env = Object.fromEntries(Object.entries(childEnvironment()).filter(([key]) => !key.startsWith('MACWARDEN_')));
const connection = ['--lnd-rest', '127.0.0.1:1', '--tls-cert', 'tls.cert', '--macaroon', 'own.macaroon'];

function cli(args: string[]) {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), ...args],
    { env, encoding: 'utf8', timeout: 30_000, windowsHide: true });
  return { status: run.status, stderr: run.stderr, stdout: run.stdout };
}

const cases: [string, string[], RegExp][] = [
  ['bake without a label', ['bake'], /^error: B1: --label is required$/m],
  ['bake label rule', ['bake', '--label', '1app', '--out', 'x'], /--label must start with a letter and contain only letters, digits/],
  ['bake missing REST address', ['bake', '--label', 'App', '--out', 'x'], /--lnd-rest \(or MACWARDEN_LND_REST\) is required/],
  ['bake missing TLS certificate', ['bake', '--label', 'App', '--out', 'x', '--lnd-rest', '127.0.0.1:1'], /--tls-cert \(or MACWARDEN_TLS_CERT\) is required/],
  ['bake missing own macaroon', ['bake', '--label', 'App', '--out', 'x', '--lnd-rest', '127.0.0.1:1', '--tls-cert', 't'], /--macaroon \(or MACWARDEN_MACAROON\) is required/],
  ['bake bad REST address', ['bake', '--label', 'App', '--out', 'x', ...connection.slice(2), '--lnd-rest', 'https://h:1/p'], /--lnd-rest \(or MACWARDEN_LND_REST\) must be host:port/],
  ['bake unknown preset lists presets', ['bake', '--label', 'App', '--out', 'x', ...connection, '--preset', 'everything'], /unknown --preset; valid presets: read-only, invoice-only, pay-only, btcpay/],
  ['bake expiry unit', ['bake', '--label', 'App', '--out', 'x', ...connection, '--preset', 'read-only', '--expires', '90'], /--expires must be 1 to 99999 followed by m \(minutes\), h \(hours\) or d \(days\)/],
  ['bake repeated flag', ['bake', '--label', 'A', '--label', 'B'], /--label was given more than once/],
  ['bake missing value', ['bake', '--label'], /--label needs a value/],
  ['bake unknown argument', ['bake', '--frob'], /unknown argument; bake takes only flags: --label/],
  ['inventory missing REST address', ['inventory'], /--lnd-rest \(or MACWARDEN_LND_REST\) is required/],
  ['inventory unknown argument', ['inventory', '--frob'], /unknown argument; inventory takes only flags: --lnd-rest --tls-cert --macaroon --registry --expiring-within --report --out --verify --json/],
  ['inventory missing value', ['inventory', '--registry'], /--registry needs a value/],
  ['revoke root key ID 0', ['revoke', '0', ...connection], /^error: V1: root key ID 0 cannot be revoked/m],
  ['revoke without a target', ['revoke', ...connection], /give one target: a label .* or a root key ID from 1 to 18446744073709551615/],
  ['revoke literal target file', ['revoke', 'App', ...connection, '--target-file', '-'], /--target-file must be a file path/],
  ['recommend stdin target file', ['recommend', ...connection, '--target-file', '-'], /--target-file must be a file path; stdin \(-\) and literal credentials are refused/],
  ['rotate stage without --out', ['rotate', 'App', ...connection], /^error: S1: --out is required for the stage run/m],
  ['rotate finish with --out', ['rotate', 'App', '--finish', '--out', 'x', ...connection], /^error: F1: --out is not used with --finish/m],
  ['rotate stage with --yes', ['rotate', 'App', '--out', 'x', '--yes', ...connection], /--yes is only used with --finish/],
  ['attenuate without input', ['attenuate', '--out', 'x', '--expires', '1h'], /give exactly one input: a macaroon file path or - \(stdin\)/],
  ['attenuate expiry unit', ['attenuate', 'in', '--out', 'x', '--expires', '1w'], /--expires must be 1 to 99999 followed by m/],
  ['scan grade list', ['scan', '.', '--fail-on', 'HIGH'], /--fail-on takes one grade: ADMIN, SPEND, OPERATE, RECEIVE, READ \(any case\)/],
  ['scan unknown flag', ['scan', '--frob'], /unknown flag; scan takes: \[paths\.\.\.\] --fail-on/],
];

it.each(cases)('UX/error-messages %s names the flag and the rule', (_name, args, message) => {
  const run = cli(args);
  expect(run.status).toBe(2);
  expect(run.stderr).toMatch(message);
});

it('UX/error-messages a credential given in place of a value is never repeated in the refusal', () => {
  const vector = readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));
  for (const value of [vector.toString('hex'), vector.toString('base64')]) {
    for (const args of [['bake', '--label', value], ['revoke', value, ...connection], ['rotate', value, ...connection],
      ['bake', '--label', 'App', '--out', 'x', ...connection, '--preset', value]]) {
      const run = cli(args);
      expect(run.status).toBe(2);
      expect(run.stderr + run.stdout).not.toContain(value.slice(0, 40));
    }
  }
});
