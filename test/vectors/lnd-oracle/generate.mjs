// Records the LND v0.21.4 oracle's verdict on every case in cases.mjs (go-macaroon
// v2.0.0, macaroon-bakery v2.0.1 and the protobuf fork pinned by LND's go.mod, plus copies
// of macaroons.Service.CheckMacAuth's structure checks and LND's caveat checkers; source in
// ./oracle). Build it with `go build -o oracle .` in ./oracle, then run
// `node test/vectors/lnd-oracle/generate.mjs <oracle binary> m1|m2|l4 ...`. Each set is
// written to <set>.json; long values are stored as digests (see digest()) to keep it small.
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { m1, m2, NOW, ROOT_KEY, TIMES } from './cases.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
/** Texts over 128 characters are recorded as "sha256:<hex>:<length>"; tests apply the same rule. */
export const digest = text => text.length > 128 ? `sha256:${sha256(Buffer.from(text, 'utf8'))}:${text.length}` : text;
/** Consecutive equal values as [value, count] pairs. */
const runs = values => values.reduce((out, value) => {
  const last = out.at(-1);
  if (last && JSON.stringify(last[0]) === JSON.stringify(value)) last[1]++; else out.push([value, 1]);
  return out;
}, []);

function oracle(binary) {
  const child = spawn(binary, [], { stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = createInterface({ input: child.stdout });
  const waiting = [];
  lines.on('line', line => waiting.shift()(JSON.parse(line)));
  const ask = line => new Promise(resolve => { waiting.push(resolve); child.stdin.write(`${line}\n`); });
  return { ask, close: () => child.stdin.end() };
}

const [binary, ...wanted] = process.argv.slice(2);
if (!binary || wanted.length === 0) throw new Error('usage: generate.mjs <oracle binary> m1|m2|l4 ...');
const o = oracle(binary);
for (const name of wanted) {
  const cases = [];
  if (name === 'l4') {
    for (const value of TIMES) {
      const answer = await o.ask(`T ${Buffer.from(value).toString('hex')}`);
      cases.push({ value, lnd: answer.ok ? { ok: true, unixSeconds: answer.sec, nanos: answer.nsec } : { ok: false } });
    }
  } else {
    for (const [caseName, bytes] of Object.entries({ m1, m2 }[name]())) {
      const r = await o.ask(`M ${bytes.toString('hex')}`);
      cases.push({ name: caseName, sha256: sha256(bytes), length: bytes.length, lnd: {
        parse: r.parse, verify: r.verify, error: r.err || r.verifyErr || null,
        location: r.parse ? r.location : null,
        identifierSha256: r.parse ? sha256(Buffer.from(r.idHex, 'hex')) : null,
        canonicalSha256: r.canonHex ? sha256(Buffer.from(r.canonHex, 'hex')) : null,
        storageId: r.storageId ? Buffer.from(r.storageId, 'hex').toString('latin1') : null,
        ops: r.ops ? runs(r.ops.map(digest)) : null,
        caveats: r.parse ? runs((r.cavs ?? []).map(c => ({ location: c.loc, id: digest(Buffer.from(c.id, 'hex').toString('latin1')),
          vidLength: c.vid.length / 2 }))) : null,
        allow: r.allow && Object.keys(r.allow).length ? r.allow : null } });
    }
  }
  writeFileSync(new URL(`./${name}.json`, import.meta.url), `${JSON.stringify({
    source: 'LND v0.21.4-beta macaroon oracle (test/vectors/lnd-oracle/oracle)', rootKey: ROOT_KEY, clock: NOW, cases }, null, 1)}\n`);
  console.log(`${name}: ${cases.length} cases`);
}
o.close();
