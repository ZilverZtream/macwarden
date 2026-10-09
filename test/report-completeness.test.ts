import { writeFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { render } from '../src/output/index.js';
import { entry, fixture, instant, nextId, oldId, ownId, pubkey, type Entry } from './helpers/cp038-online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

// MW102-11: every format of the access review carries the evidence the JSON review carries.
// Registry: Alice rotated (old revoked, replacedBy the new one; new replaces the old), a
// triggered canary, Bob ADMIN without expiry. LND has root key 0, the own key and an unknown ID.
// The node alias and version are hostile: formula characters, Markdown and HTML metacharacters,
// a CSV quote, a comma and a control character.
const canaryId = 4294967350n, bobId = 4294967351n, unknownId = 900000000002n;
const hostileAlias = '=HYPERLINK("http://x",",|<b>[a](b)")\u0007';
const hostileVersion = '@0.21|<i>';

type Review = {
  generatedAt: string; macwardenVersion: string; node: Record<string, string>; limitations: string;
  credentials: { rootKeyId: string; inLnd: boolean; label: string | null; status: string; grade: string | null;
    permissions: string[]; caveats: string[]; expiresAt: string | null; createdAt: string | null; revokedAt: string | null;
    revokeEvidence: string | null; replaces: string | null; replacedBy: string | null; lastUsed: string | null;
    calls: number | null; canary: { uses: number; firstUse: string; lastUse: string } | null; flags: string[] }[];
  totals: { inLnd: number; active: number; revoked: number; unknown: number; flagged: Record<string, number> };
  controls: { control: string; observation: string; rootKeyIds: string[] }[];
  signOff: Record<string, null>;
};

function setup() {
  const f = fixture();
  const old: Entry = { ...f.old, status: 'revoked', revokedAt: '2026-10-04T00:00:00.000Z', revokeEvidence: 'rejected', replacedBy: String(nextId),
    caveats: [{ type: 'time-before', value: '2027-01-01T00:00:00Z' }] };
  const next: Entry = { ...f.next, caveats: [{ type: 'time-before', value: '2027-02-01T00:00:00Z' }] };
  const canary: Entry = { ...entry(canaryId, 'Decoy'), caveats: [{ type: 'lnd-custom', value: 'policy-3597f768 44d9b8b458bc3481' }] };
  const bob: Entry = { ...entry(bobId, 'Bob'), grade: 'ADMIN' };
  f.save([old, next, canary, bob]);
  f.lnd.ids = [0n, ownId, nextId, canaryId, bobId, unknownId];
  f.lnd.info = { ...f.lnd.info, alias: hostileAlias, version: hostileVersion };
  writeFileSync(`${f.registry}.usage.json`, JSON.stringify({ schema: 1, dropped: 0,
    canaryUses: [{ nodePubkey: pubkey, rootKeyId: String(canaryId), uses: 3, firstUse: '2026-10-05T11:00:00.000Z', lastUse: '2026-10-05T11:30:00.000Z' }],
    entries: [{ nodePubkey: pubkey, credential: 'id:1111111111111111', rootKeyId: String(nextId), method: '/lnrpc.Lightning/AddInvoice',
      calls: 7, errors: 0, firstSeen: '2026-10-05T09:00:00.000Z', lastSeen: '2026-10-05T10:00:00.000Z' }] }));
  return f;
}

async function report(format: string) {
  const f = setup();
  const output = await inventory(['--report', format, ...f.flags], f.deps);
  expect(output.error).toBeNull();
  return render(output, 'text');
}

/** The JSON format of the report, the reference the other formats are compared with. */
async function jsonReview(): Promise<Review> {
  const f = setup();
  expectSchemaValid(await inventory(['--report', 'json', '--json', ...f.flags], f.deps));
  return JSON.parse(await report('json')) as Review;
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

// Independent statements of the documented escaping rules.
const md = (value: string) => value.replace(/[\\|[\]()!*_`#~]/g, c => `\\${c}`).replace(/</g, '&lt;').replace(/>/g, '&gt;') || '—';
const spreadsheet = (value: string) => /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
const plain = (value: string) => value.split('\u0007').join(' ');

it('REPORT/json carries rotation links, canary uses and the limitation statement', async () => {
  const review = await jsonReview();
  const byId = (id: bigint) => review.credentials.find(item => item.rootKeyId === String(id))!;
  expect(byId(oldId)).toMatchObject({ status: 'revoked', replacedBy: String(nextId), replaces: null });
  expect(byId(nextId)).toMatchObject({ replaces: String(oldId), lastUsed: '2026-10-05T10:00:00.000Z', calls: 7, canary: null });
  expect(byId(canaryId).canary).toEqual({ uses: 3, firstUse: '2026-10-05T11:00:00.000Z', lastUse: '2026-10-05T11:30:00.000Z' });
  expect(byId(canaryId).flags).toContain('canary-triggered');
  expect(review.limitations).toMatch(/does not by itself establish compliance with any framework/);
  expect(review.node.alias).toBe(plain(hostileAlias));
});

it('REPORT/markdown carries every field of every credential and every report-level field of the JSON review', async () => {
  const review = await jsonReview();
  const text = await report('markdown');
  const lines = text.split('\n');
  // Report identity and limitations.
  expect(lines).toContain(`- Generated: ${md(review.generatedAt)}`);
  expect(lines).toContain(`- Tool: macwarden ${md(review.macwardenVersion)}`);
  expect(lines).toContain(`- Node: ${md(review.node.pubkey)} (${md(review.node.alias)}), ${md(review.node.network)}, LND ${md(review.node.version)}`);
  expect(text).toContain(review.limitations);
  // Totals, including every flag count.
  expect(lines).toContain(`- Root key IDs in LND: ${review.totals.inLnd}; active registry entries: ${review.totals.active}; revoked: ${review.totals.revoked}; unknown: ${review.totals.unknown}`);
  expect(lines).toContain(`- Flag counts: ${Object.entries(review.totals.flagged).map(([flag, count]) => `${md(flag)} ${count}`).join(', ')}`);
  // One table row per credential, every column the JSON field it states.
  const header = lines.find(line => line.startsWith('| Root key ID |'))!.split(' | ');
  expect(header.map(cell => cell.replace(/^\| | \|$/g, ''))).toEqual(['Root key ID', 'In LND', 'Label', 'Status', 'Grade', 'Expires', 'Created',
    'Revoked', 'Evidence', 'Replaces', 'Replaced by', 'Last used', 'Calls', 'Canary uses', 'Flags']);
  for (const item of review.credentials) {
    const row = lines.find(line => line.startsWith(`| ${item.rootKeyId} |`));
    expect(row, item.rootKeyId).toBeDefined();
    const cells = row!.slice(2, -2).split(/(?<!\\) \| /);
    const canary = item.canary ? `${item.canary.uses} denied (first ${item.canary.firstUse}, last ${item.canary.lastUse})` : '';
    expect(cells).toEqual([item.rootKeyId, item.inLnd ? 'yes' : 'no', item.label ?? '', item.status, item.grade ?? '', item.expiresAt ?? '',
      item.createdAt ?? '', item.revokedAt ?? '', item.revokeEvidence ?? '', item.replaces ?? '', item.replacedBy ?? '',
      item.lastUsed ?? 'not observed', item.calls === null ? '' : String(item.calls), canary, item.flags.join(', ')].map(md));
  }
  // Permissions and caveats per credential that has them.
  for (const item of review.credentials) {
    if (item.permissions.length) expect(lines).toContain(`- ${md(item.rootKeyId)} ${md(item.label ?? '')}: ${item.permissions.map(md).join(', ')}`);
    if (item.caveats.length) expect(lines).toContain(`- ${md(item.rootKeyId)} ${md(item.label ?? '')}: ${item.caveats.map(md).join('; ')}`);
  }
  expect(lines).toContain('## Caveats');
  // Controls with their observations and IDs; then the empty sign-off.
  for (const control of review.controls) {
    const at = lines.indexOf(`### ${control.control}`);
    expect(at, control.control).toBeGreaterThan(0);
    expect(lines[at + 2]).toBe(control.observation);
    expect(lines[at + 4]).toBe(control.rootKeyIds.length ? `Root key IDs: ${control.rootKeyIds.map(md).join(', ')}` : 'Root key IDs: none');
  }
  expect(Object.values(review.signOff).every(value => value === null)).toBe(true);
  expect(lines).toContain('## Reviewer sign-off');
  for (const field of ['| Reviewer | |', '| Date | |', '| Decision (approved / changes required) | |', '| Notes | |']) expect(lines).toContain(field);
  // Hostile text is inert: no raw HTML tag, no unescaped table pipe or link syntax from the alias.
  expect(text).not.toMatch(/<b>|<i>/);
  expect(text).not.toContain('[a](b)');
  // eslint-disable-next-line no-control-regex
  expect(text).not.toMatch(/[\x00-\x08\x0b-\x1f\x7f]/);
});

it('REPORT/csv is one table with one header row whose columns carry every credential and report-level field', async () => {
  const review = await jsonReview();
  const text = await report('csv');
  expect(text.endsWith('\r\n')).toBe(true);
  const rows = parseCsv(text);
  const header = rows[0];
  expect(header).toEqual(['root_key_id', 'in_lnd', 'label', 'status', 'grade', 'permissions', 'expires_at', 'created_at',
    'revoked_at', 'revoke_evidence', 'replaces', 'replaced_by', 'last_used', 'calls', 'flags',
    'caveats', 'canary_uses', 'canary_first_use', 'canary_last_use', 'controls', 'control_observations',
    'generated_at', 'macwarden_version', 'node_pubkey', 'node_alias', 'node_network', 'node_version',
    'reviewer', 'review_date', 'review_decision', 'review_notes', 'limitations']);
  const body = rows.slice(1);
  // Exactly one header: no later row repeats it, every row is as wide, one row per credential.
  expect(body.every(row => row.length === header.length)).toBe(true);
  expect(body.some(row => row[0] === 'root_key_id')).toBe(false);
  expect(body.map(row => row[0])).toEqual(review.credentials.map(item => item.rootKeyId));
  const column = (row: string[], name: string) => row[header.indexOf(name)];
  for (const item of review.credentials) {
    const row = body.find(cells => cells[0] === item.rootKeyId)!;
    const expected: Record<string, string> = {
      in_lnd: String(item.inLnd), label: item.label ?? '', status: item.status, grade: item.grade ?? '', permissions: item.permissions.join(' '),
      expires_at: item.expiresAt ?? '', created_at: item.createdAt ?? '', revoked_at: item.revokedAt ?? '', revoke_evidence: item.revokeEvidence ?? '',
      replaces: item.replaces ?? '', replaced_by: item.replacedBy ?? '', last_used: item.lastUsed ?? '', calls: item.calls === null ? '' : String(item.calls),
      flags: item.flags.join(' '), caveats: item.caveats.join('; '),
      canary_uses: item.canary ? String(item.canary.uses) : '', canary_first_use: item.canary?.firstUse ?? '', canary_last_use: item.canary?.lastUse ?? '',
      controls: review.controls.filter(control => control.rootKeyIds.includes(item.rootKeyId)).map(control => control.control).join('; '),
      control_observations: review.controls.filter(control => control.rootKeyIds.includes(item.rootKeyId))
        .map(control => `${control.control}: ${control.observation}`).join(' | '),
      generated_at: review.generatedAt, macwarden_version: review.macwardenVersion, node_pubkey: review.node.pubkey,
      node_alias: review.node.alias, node_network: review.node.network, node_version: review.node.version,
      reviewer: '', review_date: '', review_decision: '', review_notes: '', limitations: review.limitations,
    };
    for (const [name, value] of Object.entries(expected)) expect(column(row, name), `${item.rootKeyId} ${name}`).toBe(spreadsheet(value));
  }
  // Every control that names an ID is reachable from the rows; its ID set is exactly the rows naming it.
  for (const control of review.controls)
    expect(body.filter(row => column(row, 'controls').split('; ').includes(control.control)).map(row => row[0])).toEqual(control.rootKeyIds);
  // Totals are derivable from the rows.
  expect(body.filter(row => column(row, 'in_lnd') === 'true')).toHaveLength(review.totals.inLnd);
  for (const [flag, count] of Object.entries(review.totals.flagged))
    expect(body.filter(row => column(row, 'flags').split(' ').includes(flag)), flag).toHaveLength(count);
  // The hostile alias is neutralised for spreadsheets and kept as data.
  expect(column(body[0], 'node_alias')).toBe(`'${plain(hostileAlias)}`);
  expect(column(body[0], 'node_version')).toBe(`'${hostileVersion}`);
  expect(review.credentials.find(item => item.rootKeyId === String(canaryId))!.canary).not.toBeNull();
  expect(new Date(instant).toISOString()).toBe(review.generatedAt);
});
