import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { findLeaks } from "./leak-check.js";

export const repo = resolve();
const base = resolve('test/oracle/btcpay');
export const manifest = JSON.parse(readFileSync(join(base, 'manifest.json'), 'utf8'));
const sorted = values => [...new Set(values)].sort();
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function requireReference(condition, message) {
  if (!condition) throw new Error(`BTCPay source attribution: ${message}`);
}
export function validateManifest(value = manifest) {
  const client = readFileSync(join(base, 'LndClient.cs'), 'utf8');
  for (const record of Object.values(value.sources)) {
    requireReference(/^[0-9a-f]{40}$/.test(record.revision), 'mutable source revision');
    if (record.local) {
      const bytes = readFileSync(join(base, record.local));
      requireReference(digest(bytes) === record.sha256, `changed source ${record.path}`);
      requireReference(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') === record.gitBlob,
        `Git blob mismatch ${record.path}`);
    }
  }
  const csproj = readFileSync(join(base, 'BTCPayServer.csproj'), 'utf8');
  requireReference(csproj.includes('Include="BTCPayServer.Lightning.All" Version="1.7.8"'), 'server dependency changed');
  requireReference(readFileSync(join(base, 'all.nuspec'), 'utf8').includes('id="BTCPayServer.Lightning.LND" version="1.7.2"'),
    'All -> LND dependency changed');
  requireReference(readFileSync(join(base, 'lnd.nuspec'), 'utf8').includes(`commit="${value.clientRevision}"`), 'package source revision changed');
  const helpers = sorted([...client.matchAll(/SwaggerClient\.([A-Za-z]+)\(/g)].map(match => match[1]));
  requireReference(JSON.stringify(helpers) === JSON.stringify(sorted(value.calls.map(call => call.helper).filter(Boolean))),
    'required helper omitted or invented');
  const direct = sorted([...client.matchAll(/HttpRequestMessage\(HttpMethod\.\w+, WithTrailingSlash\(_Parent.BaseUrl\) \+ \$?"([^"]+)"/g)]
    .map(match => match[1]));
  requireReference(JSON.stringify(direct) === JSON.stringify(sorted(value.calls.map(call => call.direct).filter(Boolean))),
    'direct stream call omitted or invented');
  const snapshotBytes = readFileSync(resolve('src/grade/lnd-permissions.json'));
  requireReference(digest(snapshotBytes) === value.snapshotSha256, 'permission snapshot changed; recapture attribution');
  const snapshot = JSON.parse(snapshotBytes);
  requireReference(value.supportedVersion === 'BTCPay Server v2.4.4' && snapshot.lndVersion === value.lndVersion,
    'unsupported version claim');
  requireReference(new Set(value.calls.map(call => call.method)).size === value.calls.length, 'duplicate method');
  for (const call of value.calls) {
    requireReference(call.clientLocations.length > 0, `missing client location ${call.method}`);
    for (const location of call.clientLocations) {
      requireReference(client.split('\n')[location.line - 1] === location.text, `wrong client line ${call.method}`);
    }
    requireReference(call.permissionsSource.text.includes(`"${call.method}"`), `wrong permission source ${call.method}`);
    const parsed = [...call.permissionsSource.text.matchAll(/Entity: "([^"]+)",\s+Action: "([^"]+)"/g)]
      .map(match => `${match[1]}:${match[2]}`);
    requireReference(parsed.length > 0 && JSON.stringify(parsed) === JSON.stringify(call.permissions) &&
      JSON.stringify(parsed) === JSON.stringify(snapshot.methods[call.method]), `unassessed or unmapped method ${call.method}`);
    for (const location of [call.permissionsSource, call.restMapping, ...call.endpointSources]) {
      requireReference(Boolean(value.sources[location.source]) && location.line > 0 && location.text.length > 0,
        `missing primary attribution ${call.method}`);
    }
    requireReference(call.restMapping.text.includes(call.method.slice(1).replace('/', '.')), `wrong REST selector ${call.method}`);
    if (call.helper) requireReference(call.endpointSources.some(location => location.text.includes(`${call.helper}(`)),
      `missing called helper path ${call.method}`);
    requireReference(call.lncli.args !== null || Boolean(call.lncli.blocker), `missing probe attribution ${call.method}`);
  }
  const expected = value.calls.map(call => `uri:${call.method}`).sort();
  requireReference(JSON.stringify(value.permissions) === JSON.stringify(expected), 'permission set differs from required calls');
  requireReference(!value.calls.some(call => call.method === value.forbidden.method), 'forbidden call is required');
  return value;
}

export function suite(kind) {
  const parent = process.env.MACWARDEN_TEST_TMP;
  if (!parent) throw new Error('MACWARDEN_TEST_TMP is required');
  mkdirSync(parent, { recursive: true });
  const dir = mkdtempSync(join(resolve(parent), `cp034-${kind}-`));
  const sentinelDir = join(dir, 'sentinels');
  mkdirSync(sentinelDir, { mode: 0o700 });
  const previous = { tmp: process.env.MACWARDEN_TEST_TMP, sentinels: process.env.MACWARDEN_SENTINEL_DIR };
  process.env.MACWARDEN_TEST_TMP = dir;
  process.env.MACWARDEN_SENTINEL_DIR = sentinelDir;
  const outputs = [];
  return { dir, sentinelDir, previous, outputs, leak: () => findLeaks({ root: repo,
    sentinels: resolve('test/sentinels.json'), sentinelDir, testTmp: dir,
    commandOutput: outputs.join('\n'), paths: [dir] }) };
}
