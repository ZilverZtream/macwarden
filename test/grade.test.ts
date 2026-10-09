import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';

type Grade = 'ADMIN' | 'SPEND' | 'OPERATE' | 'RECEIVE' | 'READ' | 'UNASSESSED';
type Result = { grade: Grade; reasons: string[]; warnings: string[]; unassessed: string[] };
type Facts = { location: string | null; rootKeyId: bigint; permissions: string[];
  caveats: { type: string; value: string }[]; fingerprint: string; warnings: string[] };
type Grader = { grade: (permissions: string[]) => Result; describe: (facts: Facts) => string[] };
const repo = resolve();
const vectors = join(repo, 'test/vectors');

const grader = (): Promise<Grader> => import('../src/grade/index.js') as Promise<Grader>;
const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as {
  methods: Record<string, string[]>;
};
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; expectedGrade: Grade }[];
};
const printed = (name: string): string[] => (JSON.parse(readFileSync(join(vectors, `${name}.printmacaroon.json`), 'utf8')) as {
  permissions: string[];
}).permissions;
const byteSort = (values: string[]) => [...values].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));

const referenceRows: { name: string; permissions: string[]; expected: Grade }[] = [
  { name: 'default admin', permissions: printed('default-admin'), expected: 'ADMIN' },
  { name: 'default readonly', permissions: printed('default-readonly'), expected: 'READ' },
  { name: 'default invoice', permissions: printed('default-invoice'), expected: 'RECEIVE' },
  { name: 'admin pair', permissions: ['info:read', 'macaroon:generate'], expected: 'ADMIN' },
  { name: 'offchain spend pair', permissions: ['offchain:read', 'offchain:write'], expected: 'SPEND' },
  { name: 'signer read', permissions: ['signer:read'], expected: 'READ' },
  { name: 'info write', permissions: ['info:write'], expected: 'OPERATE' },
  { name: 'onchain generate', permissions: ['onchain:generate'], expected: 'SPEND' },
  { name: 'peers pair', permissions: ['peers:read', 'peers:write'], expected: 'OPERATE' },
  { name: 'disconnect peer URI', permissions: ['uri:/lnrpc.Lightning/DisconnectPeer'], expected: 'OPERATE' },
  { name: 'invoice and send URI', permissions: ['invoices:read', 'uri:/routerrpc.Router/SendPaymentV2'], expected: 'SPEND' },
  { name: 'read URI pair', permissions: ['uri:/lnrpc.Lightning/GetInfo', 'uri:/lnrpc.Lightning/ListInvoices'], expected: 'READ' },
  { name: 'add invoice URI', permissions: ['uri:/lnrpc.Lightning/AddInvoice'], expected: 'RECEIVE' },
  { name: 'pay-only preset', permissions: printed('preset-pay-only'), expected: 'SPEND' },
];

it.each(referenceRows)('CP-007/B1 $name follows the grade ladder', async ({ permissions, expected }) => {
  const { grade } = await grader();
  const result = grade(permissions);
  expect(result.grade).toBe(expected);
  expect(result.unassessed).toEqual([]);
});

it('CP-007/B2 unknown URI, entity and action fail closed', async () => {
  const { grade } = await grader();
  expect(grade(['uri:/example.Unknown/Method'])).toEqual({ grade: 'UNASSESSED', reasons: [],
    warnings: ['unassessed-uri'], unassessed: ['uri:/example.Unknown/Method'] });
  expect(grade(['info:read', 'loop:write'])).toEqual({ grade: 'UNASSESSED', reasons: [],
    warnings: ['unassessed-permission'], unassessed: ['loop:write'] });
  for (const permission of ['remotesigner:generate', 'info:delete']) {
    expect(grade([permission])).toEqual({ grade: 'UNASSESSED', reasons: [],
      warnings: ['unassessed-permission'], unassessed: [permission] });
  }
});

it('CP-007/B3 malformed permissions are unassessed verbatim', async () => {
  const { grade } = await grader();
  for (const permission of ['info', 'info:', ':read', 'INFO:READ', 'uri:', 'uri:read']) {
    expect(grade([permission])).toEqual({ grade: 'UNASSESSED', reasons: [],
      warnings: ['unassessed-permission'], unassessed: [permission] });
  }
});

it('CP-007/B4 ADMIN dominates an unknown permission but retains its warning', async () => {
  const { grade } = await grader();
  expect(grade(['macaroon:generate', 'loop:write'])).toEqual({ grade: 'ADMIN',
    reasons: ['macaroon:generate'], warnings: ['unassessed-permission'], unassessed: ['loop:write'] });
});

it('CP-007/B5 empty input warns and duplicate permissions count once', async () => {
  const { grade } = await grader();
  expect(grade([])).toEqual({ grade: 'UNASSESSED', reasons: [], warnings: ['no-permissions'], unassessed: [] });
  expect(grade(['info:read', 'info:read'])).toEqual({ grade: 'READ', reasons: ['info:read'], warnings: [], unassessed: [] });
});

it('CP-007/B6 reasons, unassessed and warnings use UTF-8 byte order', async () => {
  const { grade } = await grader();
  const spend = grade(['onchain:write', 'info:read', 'offchain:write']);
  expect(spend.grade).toBe('SPEND');
  expect(spend.reasons).toEqual(['offchain:write', 'onchain:write']);
  expect(grade(['zeta:write', 'alpha:read']).unassessed).toEqual(['alpha:read', 'zeta:write']);
  expect(grade(['uri:/example.Unknown/Method', 'loop:write']).warnings)
    .toEqual(['unassessed-permission', 'unassessed-uri']);
  for (const result of [spend, grade(['zeta:write', 'alpha:read']), grade(['uri:/example.Unknown/Method', 'loop:write'])]) {
    for (const list of [result.reasons, result.warnings, result.unassessed]) expect(list).toEqual(byteSort(list));
  }
});

it('CP-007/B7 URI and fallback class boundaries follow the table', async () => {
  const { grade } = await grader();
  for (const [permission, expected] of [
    ['uri:/autopilotrpc.Autopilot/ModifyStatus', 'SPEND'], ['signer:write', 'SPEND'],
    ['address:generate', 'SPEND'], ['macaroon:read', 'READ'], ['message:write', 'OPERATE'],
    ['address:write', 'RECEIVE'],
  ] as [string, Grade][]) expect(grade([permission]).grade, permission).toBe(expected);
});

it('CP-007/B8 pay-only grades SPEND from snapshot method permissions', async () => {
  const { grade } = await grader();
  for (const method of ['/routerrpc.Router/SendPaymentV2', '/routerrpc.Router/TrackPaymentV2',
    '/lnrpc.Lightning/DecodePayReq']) expect(Object.hasOwn(snapshot.methods, method)).toBe(true);
  const result = grade(printed('preset-pay-only'));
  expect(result.grade).toBe('SPEND');
  expect(result.reasons).toEqual(['uri:/routerrpc.Router/SendPaymentV2']);
});

it('CP-007/B9 read access has no preimage warning before assumption 10', async () => {
  const { grade } = await grader();
  for (const permission of ['invoices:read', 'offchain:read']) {
    const result = grade([permission]);
    expect(result.grade).toBe('READ');
    expect(result.warnings).toEqual([]);
  }
});

it('CP-007/B10 macaroon generation dominates every stored and sampled set', async () => {
  const { grade } = await grader();
  for (const vector of manifest.vectors) {
    const permissions = printed(vector.name);
    if (permissions.includes('macaroon:generate')) expect(grade(permissions).grade, vector.name).toBe('ADMIN');
  }
  const known = ['onchain', 'offchain', 'address', 'message', 'peers', 'info', 'invoices', 'signer', 'macaroon']
    .flatMap(entity => ['read', 'write', 'generate'].map(action => `${entity}:${action}`));
  let state = 0x007c0de;
  const next = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
  for (let sample = 0; sample < 200; sample++) {
    const subset = known.filter(() => (next() & 3) === 0);
    subset.push('macaroon:generate');
    expect(grade(subset).grade, `sample ${sample}`).toBe('ADMIN');
  }
});

it('CP-007/B11 describe adds root key and decoder warnings', async () => {
  const { describe } = await grader();
  const facts: Facts = { location: 'lnd', rootKeyId: 0n, permissions: ['info:read'], caveats: [],
    fingerprint: 'fp:0000000000000000', warnings: [] };
  expect(describe(facts)).toEqual(['root-key-0']);
  expect(describe({ ...facts, rootKeyId: 5n, warnings: ['trailing-bytes'] })).toEqual(['trailing-bytes']);
  expect(describe({ ...facts, rootKeyId: 5n, warnings: ['bad-time-before'] })).toEqual(['bad-time-before']);
  expect(describe({ ...facts, rootKeyId: 5n })).toEqual([]);
});

it('CP-007/B12 grade module imports neither filesystem, HTTP nor LND code', () => {
  const dir = join(repo, 'src/grade');
  const files = (function list(path: string): string[] {
    return readdirSync(path, { withFileTypes: true }).flatMap(entry =>
      entry.isDirectory() ? list(join(path, entry.name)) : entry.isFile() ? [join(path, entry.name)] : []);
  })(dir).filter(path => /\.[cm]?[jt]s$/.test(path));
  expect(files.length).toBeGreaterThan(0);
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    const imports = [...source.matchAll(/\b(?:import|export)\s+(?:[^;]*?\s+from\s+)?['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g)]
      .map(match => match[1] || match[2]);
    for (const target of imports) {
      const destination = target.startsWith('.') ? resolve(join(file, '..'), target) : target;
      expect(!destination.includes(`${sep}src${sep}lnd${sep}`)
        && !['node:fs', 'node:http', 'node:https'].includes(target), relative(repo, file)).toBe(true);
    }
  }
});

it('CP-007/B13 pinned GetInfo requirement grades READ', async () => {
  const { grade } = await grader();
  const method = '/lnrpc.Lightning/GetInfo';
  // Pinned live ListPermissions observation: test/oracle/facts/observations.json uriGetInfo.
  expect(snapshot.methods[method]).toEqual(['info:read']);
  expect(grade([`uri:${method}`])).toEqual({ grade: 'READ',
    reasons: [`uri:${method}`], warnings: [], unassessed: [] });
});
