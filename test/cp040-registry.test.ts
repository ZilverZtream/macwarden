import Ajv2020 from 'ajv/dist/2020.js';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { fixture } from './helpers/cp038-online.js';
import { run } from '../src/commands/bake/index.js';

const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({strict:true}).compile(
  JSON.parse(readFileSync(resolve('schemas/output/registry-entry.schema.json'), 'utf8')));

it('CP-040/B11-meaningful-tests pending schema permits null identity only without a verified credential or output path', () => {
  const f = fixture(), pending = {...f.old,fingerprint:null,verified:false,outPath:null};
  expect(validate(pending)).toBe(true);
  expect(validate({...pending,verified:true})).toBe(false);
  expect(validate({...pending,outPath:f.old.outPath})).toBe(false);
  expect(validate(f.old)).toBe(true);
});
it('CP-040/B11-meaningful-tests bake journals null pending identity before mutation and finalizes the exact file fingerprint', async () => {
  const f = fixture();
  let observed = false;
  f.lnd.onBake = id => {
    const row = f.rows().find(entry => entry.rootKeyId === String(id));
    expect(row).toMatchObject({label:'Bob',status:'active',verified:false,fingerprint:null,outPath:null});
    expect(validate(row)).toBe(true); observed = true;
  };
  const result = await run(['--label','Bob','--preset','invoice-only','--out',f.out,...f.flags],f.deps);
  expect(observed).toBe(true); expect(result.error).toBeNull();
  const row = f.rows().find(entry => entry.label === 'Bob');
  expect(row).toMatchObject({verified:true,outPath:f.out,
    fingerprint:'fp:'+createHash('sha256').update(readFileSync(f.out)).digest('hex').slice(0,16)});
  expect(validate(row)).toBe(true);
});
