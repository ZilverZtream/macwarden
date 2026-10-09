import { expect, it } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { render } from '../src/output/index.js';
import { UsageStore, usagePath, writeUsage } from '../src/watch/usage.js';
import { entry, fixture, oldId, ownId } from './helpers/cp038-online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

// A real watch usage file next to the registry: Alice (oldId) made three successful calls
// over two methods and one failed call; root key 0 made two calls; Bob made none.
// Expected values below are worked out by hand from these records.
const bobId = 4294967401n;

async function setup() {
  const f = fixture();
  f.save([f.old, entry(bobId, 'Bob')]);
  f.lnd.ids = [0n, ownId, oldId, bobId];
  const node = f.old.nodePubkey;
  const store = new UsageStore();
  store.record(node, 'id:aaaaaaaaaaaaaaaa', String(oldId), '/lnrpc.Lightning/GetInfo', new Date('2026-10-03T08:00:00Z'));
  store.record(node, 'id:aaaaaaaaaaaaaaaa', String(oldId), '/lnrpc.Lightning/GetInfo', new Date('2026-10-04T09:30:00Z'));
  store.record(node, 'id:aaaaaaaaaaaaaaaa', String(oldId), '/lnrpc.Lightning/AddInvoice', new Date('2026-10-02T10:00:00Z'));
  store.record(node, 'id:aaaaaaaaaaaaaaaa', String(oldId), '/lnrpc.Lightning/AddInvoice', new Date('2026-10-05T11:00:00Z'), true);
  store.record(node, 'id:bbbbbbbbbbbbbbbb', '0', '/lnrpc.Lightning/GetInfo', new Date('2026-10-01T00:00:00Z'));
  store.record(node, 'id:cccccccccccccccc', '0', '/lnrpc.Lightning/ListChannels', new Date('2026-10-01T06:00:00Z'));
  // Another node's records never count for this one.
  store.record('03' + 'cd'.repeat(32), 'id:dddddddddddddddd', String(bobId), '/lnrpc.Lightning/GetInfo', new Date('2026-10-05T00:00:00Z'));
  await writeUsage(usagePath(f.registry), store);
  return f;
}

function csv(text: string): Record<string, string>[] {
  const [header, ...rows] = text.trim().split('\r\n').map(line => line.split(','));
  return rows.map(row => Object.fromEntries(header.map((name, index) => [name, row[index]])));
}

it('REPORT/usage access review shows last use and call counts from the watch usage file', async () => {
  const f = await setup();
  const output = await inventory(['--report', 'csv', ...f.flags], f.deps);
  expect(output.error).toBeNull();
  const rows = Object.fromEntries(csv(render(output, 'text')).map(row => [row.root_key_id, row]));
  // The failed call (errors) is not a use; its later timestamp still updates lastSeen.
  expect(rows[String(oldId)]).toMatchObject({ last_used: '2026-10-05T11:00:00.000Z', calls: '3' });
  expect(rows['0']).toMatchObject({ last_used: '2026-10-01T06:00:00.000Z', calls: '2' });
  expect(rows[String(bobId)]).toMatchObject({ last_used: '', calls: '' });
});

it('REPORT/usage markdown says "not observed" without usage and the JSON review carries the counts', async () => {
  const f = await setup();
  const markdown = render(await inventory(['--report', 'markdown', ...f.flags], f.deps), 'text');
  const bobRow = markdown.split('\n').find(line => line.startsWith(`| ${bobId} |`))!;
  expect(bobRow).toContain('| not observed |');
  const json = await inventory(['--report', 'json', ...f.flags], f.deps);
  // The real --report output, usage included, matches the published inventory schema.
  expectSchemaValid(json);
  const review = (json.result as { report: { review: { credentials: { rootKeyId: string; calls: number | null }[] } } }).report.review;
  expect(review.credentials.find(item => item.rootKeyId === String(oldId))?.calls).toBe(3);
  expect(review.credentials.find(item => item.rootKeyId === String(bobId))?.calls).toBeNull();
});

it('REPORT/usage without a usage file every row is not observed', async () => {
  const f = fixture();
  f.save([f.old]);
  f.lnd.ids = [0n, ownId, oldId];
  const rows = csv(render(await inventory(['--report', 'csv', ...f.flags], f.deps), 'text'));
  expect(rows.every(row => row.last_used === '' && row.calls === '')).toBe(true);
});
