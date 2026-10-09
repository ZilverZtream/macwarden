import { writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';
import { readCredential } from '../src/input/index.js';
import { decodeMacaroon } from '../src/decode/index.js';
import { scan } from '../src/scan/index.js';
import { scratch, vector } from './support/cp039-audit.js';

it('CP-039/B2-renderers inspect and scan share canonical lndconnect acceptance and rejection policy', async () => scratch(async dir => {
  const v = vector('default-readonly'), encoded = v.bytes.toString('base64url');
  const url = (value: string) => `lndconnect://localhost:1?macaroon=${value}`;
  const io = { fs, stdin: Readable.from([]) }, path = join(dir, 'connection.txt');
  for (const value of [encoded, encoded + '='.repeat((4 - encoded.length % 4) % 4), encodeURIComponent(encoded)]) {
    const input = await readCredential(url(value), io, { unsafeArg: true });
    expect(decodeMacaroon(input.secret).fingerprint).toBe(v.fingerprint);
    writeFileSync(path, url(value));
    expect((await scan([path], { includeDirs: false, fs })).findings).toMatchObject([{ kind: 'lndconnect', fingerprint: v.fingerprint }]);
  }
  for (const invalid of [url(encoded + '==='), url('%20' + encoded), url(encoded + '%25'),
    url(encoded) + `&macaroon=${encoded}`, url(encoded.slice(0, -1) + '*')]) {
    await expect(readCredential(invalid, io, { unsafeArg: true })).rejects.toMatchObject({ stage: 'input-form' });
    writeFileSync(path, invalid);
    const result = await scan([path], { includeDirs: false, fs });
    // Not accepted as lndconnect, as input refuses it; since RR-01 the credential inside is still
    // reported on its own (decoded or as a candidate), never hidden by the URI that failed.
    expect(result.findings.filter(finding => finding.kind === 'lndconnect')).toEqual([]);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.every(finding => finding.kind === 'undecodable-candidate' || finding.fingerprint === v.fingerprint)).toBe(true);
    expect(result.summary.dropped).toBe(1);
  }
}));
