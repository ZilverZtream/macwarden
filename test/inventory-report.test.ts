import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { csvField } from '../src/report/access-review.js';
import { render } from '../src/output/index.js';
import { entry, fixture, instant, oldId, ownId, vector, type Entry } from './helpers/cp038-online.js';

// Registry: Alice active and present; Bob ADMIN without expiry; Carol revoked and gone;
// Dave revoked but still in LND; Erin active with an expired time-before. LND also has an
// unknown ID and root key 0. Clock: 2026-10-05T12:00:00Z.
const ids = { bob: 4294967401n, carol: 4294967402n, dave: 4294967403n, erin: 4294967404n, unknown: 900000000001n };
function setup() {
  const f = fixture();
  const bob: Entry = { ...entry(ids.bob, 'Bob'), grade: 'ADMIN', permissions: [...vector('default-admin').permissions] };
  const carol: Entry = { ...entry(ids.carol, 'Carol'), status: 'revoked', revokedAt: '2026-09-01T00:00:00.000Z', revokeEvidence: 'rejected' };
  const dave: Entry = { ...entry(ids.dave, 'Dave'), status: 'revoked', revokedAt: '2026-09-02T00:00:00.000Z', revokeEvidence: 'by-id-only' };
  const erin: Entry = { ...entry(ids.erin, 'Erin'), caveats: [{ type: 'time-before', value: '2026-10-01T00:00:00Z' }] };
  const alice: Entry = { ...f.old, caveats: [{ type: 'time-before', value: '2027-01-01T00:00:00Z' }] };
  f.save([alice, bob, carol, dave, erin]);
  f.lnd.ids = [0n, ownId, oldId, ids.bob, ids.dave, ids.erin, ids.unknown];
  return f;
}

/** Minimal independent RFC 4180 reader. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = []; let row: string[] = []; let field = ''; let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) { if (c === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (c === '"') quoted = false; else field += c; }
    else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\r' && text[i + 1] === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; }
    else field += c;
  }
  return rows;
}
const expectedFlags: Record<string, string> = {
  '0': 'default-root-key', [String(ownId)]: 'own-credential', [String(oldId)]: '',
  [String(ids.bob)]: 'admin-grade no-expiry', [String(ids.carol)]: '', [String(ids.dave)]: 'revoked-but-present',
  [String(ids.erin)]: 'expired', [String(ids.unknown)]: 'unknown',
};

it('REPORT/csv one row per root key ID including revoked entries, numerically ordered, with independent flags', async () => {
  const f = setup();
  const output = await inventory(['--report', 'csv', ...f.flags], f.deps);
  expect(output.error).toBeNull();
  const rows = parseCsv(render(output, 'text'));
  expect(rows[0]).toEqual(['root_key_id', 'in_lnd', 'label', 'status', 'grade', 'permissions', 'expires_at', 'created_at',
    'revoked_at', 'revoke_evidence', 'replaces', 'replaced_by', 'last_used', 'calls', 'flags',
    'caveats', 'canary_uses', 'canary_first_use', 'canary_last_use', 'controls', 'control_observations',
    'generated_at', 'macwarden_version', 'node_pubkey', 'node_alias', 'node_network', 'node_version',
    'reviewer', 'review_date', 'review_decision', 'review_notes', 'limitations']);
  const body = rows.slice(1);
  expect(body.map(row => row[0])).toEqual(['0', String(ownId), String(oldId), String(ids.bob), String(ids.carol),
    String(ids.dave), String(ids.erin), String(ids.unknown)]);
  for (const row of body) expect(row[14]).toBe(expectedFlags[row[0]]);
  const carol = body.find(row => row[0] === String(ids.carol))!;
  expect(carol.slice(1, 4)).toEqual(['false', 'Carol', 'revoked']);
  expect(carol[8]).toBe('2026-09-01T00:00:00.000Z'); expect(carol[9]).toBe('rejected');
  expect(body.find(row => row[0] === String(oldId))![6]).toBe('2027-01-01T00:00:00Z');
});

it('REPORT/markdown has every evidence section and control observations naming the right IDs', async () => {
  const f = setup();
  f.lnd.info = { ...f.lnd.info, alias: 'ops|node' };
  const text = render(await inventory(['--report', 'markdown', ...f.flags], f.deps), 'text');
  for (const heading of ['# Lightning credential access review', '## Credentials', '## Permissions', '## Control observations',
    '### Least privilege', '### Periodic access review', '### Prompt removal', '## Reviewer sign-off'])
    expect(text.split('\n')).toContain(heading);
  expect(text).toContain('ops\\|node');
  expect(text).toContain('does not by itself establish compliance');
  const section = (name: string) => text.slice(text.indexOf(`### ${name}`)).split('\n').find(line => line.startsWith('Root key IDs:'));
  expect(section('Least privilege')).toBe(`Root key IDs: 0, ${ids.bob}`);
  expect(section('Periodic access review')).toBe(`Root key IDs: ${ownId}, ${ids.bob}, ${ids.unknown}`);
  expect(section('Prompt removal')).toBe(`Root key IDs: ${ids.dave}, ${ids.erin}`);
});

it('REPORT/json is a self-describing review with consistent totals and an empty sign-off', async () => {
  const f = setup();
  const output = await inventory(['--report', 'json', ...f.flags], f.deps);
  const review = JSON.parse(render(output, 'text')) as { macwardenVersion: string; totals: Record<string, unknown>; credentials: unknown[] };
  expect(review).toMatchObject({ schema: 1, kind: 'macwarden-access-review', generatedAt: new Date(instant).toISOString(),
    node: { pubkey: f.lnd.info.pubkey, network: 'regtest' }, signOff: { reviewer: null, date: null, decision: null } });
  expect(review.macwardenVersion).toBe(JSON.parse(readFileSync('package.json', 'utf8')).version);
  expect(review.totals).toMatchObject({ inLnd: 7, active: 3, revoked: 2, unknown: 1 });
  expect(review.credentials).toHaveLength(8);
  // --json carries the same structured review inside the inventory envelope.
  const envelope = JSON.parse(render(await inventory(['--report', 'json', '--json', ...f.flags], f.deps), 'json'));
  expect(envelope.result.report.review.credentials).toEqual(review.credentials);
});

it('REPORT/out writes an owner-only file once, never overwrites, and runs are deterministic', async () => {
  const f = setup();
  const path = join(f.dir, 'review.md');
  const first = await inventory(['--report', 'markdown', '--out', path, ...f.flags], f.deps);
  expect(first.error).toBeNull();
  expect(render(first, 'text')).toContain(`access review (markdown) written to ${path}`);
  if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600);
  const again = await inventory(['--report', 'markdown', '--out', path, ...f.flags], f.deps);
  expect(again.error).toMatchObject({ code: 3, step: 'N7', message: 'report file already exists' });
  const printed = render(await inventory(['--report', 'markdown', ...f.flags], f.deps), 'text');
  expect(readFileSync(path, 'utf8')).toBe(printed);
});

it('REPORT/arguments refuse unknown formats and --out without --report', async () => {
  const f = setup();
  expect((await inventory(['--report', 'pdf', ...f.flags], f.deps)).error).toMatchObject({ code: 2 });
  expect((await inventory(['--out', join(f.dir, 'x.csv'), ...f.flags], f.deps)).error).toMatchObject({ code: 2, message: '--out needs --report <format>' });
  expect(existsSync(join(f.dir, 'x.csv'))).toBe(false);
});

it('REPORT/leak no format contains credential bytes', async () => {
  const f = setup();
  const files = f.rows().map(row => readFileSync(row.outPath!));
  for (const format of ['markdown', 'csv', 'json']) {
    const text = render(await inventory(['--report', format, ...f.flags], f.deps), 'text');
    for (const bytes of files) for (const form of [bytes.toString('hex'), bytes.toString('base64')])
      expect(text).not.toContain(form.slice(0, 40));
  }
});

it('REPORT/csv formula characters at the start of a field are neutralised', () => {
  expect(csvField('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
  expect(csvField('+1')).toBe("'+1");
  expect(csvField('-2')).toBe("'-2");
  expect(csvField('@a')).toBe("'@a");
  expect(csvField('plain')).toBe('plain');
  expect(csvField('a,b')).toBe('"a,b"');
});
