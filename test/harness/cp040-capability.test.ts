import { ESLint } from 'eslint';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../../src/secret.js';
import { readFileSync } from 'node:fs';
import { decodeMacaroon } from '../../src/decode/index.js';
import { vector } from '../support/cp041-controls.js';

const lint = new ESLint({ cwd: resolve() });
async function rules(code: string, file: string): Promise<(string | null)[]> {
  const [result] = await lint.lintText(code, { filePath: resolve(file) });
  expect(result.fatalErrorCount).toBe(0);
  return result.messages.filter(message => message.severity === 2).map(message => message.ruleId);
}
it('CP-040/B11-meaningful-tests Secret exposes no public or prototype credential capability', () => {
  const secret = new Secret(readFileSync(resolve('test/sentinels/sentinel.macaroon')));
  expect(Reflect.get(secret, 'reveal')).toBeUndefined();
  expect(Reflect.get(Secret.prototype, 'reveal')).toBeUndefined();
  expect(Object.values(Object.getOwnPropertyDescriptors(Secret.prototype)).some(property => property.value instanceof Uint8Array)).toBe(false);
});
it.each(['src/output/probe.ts', 'src/commands/inspect.ts', 'src/commands/bake/other.ts'])(
  'CP-003/B3 private capability import is refused at %s', async file => {
    expect(await rules("import { revealSecret } from '../secret-capability.js'; export { revealSecret };", file)).toContain('macwarden/capability-boundary');
  }, 20000);
it.each(['src/decode/probe.ts', 'src/lnd/probe.ts', 'src/commands/bake/write-out.ts'])(
  'CP-003/B4 public credential decode is allowed at %s', async file => {
    expect(await rules("import { Secret } from '../secret.js'; import { decodeMacaroon } from '../decode/index.js'; const secret = new Secret(new Uint8Array()); decodeMacaroon(secret);", file)).toEqual([]);
    const reference = vector();
    const facts = decodeMacaroon(new Secret(reference.bytes));
    expect(facts.fingerprint).toBe(reference.fingerprint);
    expect(String(facts.rootKeyId)).toBe(reference.printed.root_key_id);
    expect(facts.permissions).toEqual(reference.printed.permissions);
  });
it.each(['src/output/probe.ts', 'src/commands/inspect.ts'])(
  'CP-040/B11-meaningful-tests credential writer cannot be laundered through %s', async file => {
    expect(await rules("import { reserveOut } from '../commands/bake/write-out.js'; export { reserveOut };", file)).toContain('macwarden/capability-boundary');
  });
it.each(['node:http', 'node:http2', 'node:https', 'node:net', 'node:tls', 'node:dns', 'node:dgram', 'node:child_process', 'node:worker_threads', 'node:inspector'])(
  'CP-040/B11-meaningful-tests unapproved module cannot import %s', async module => {
    expect(await rules(`import * as api from '${module}'; export { api };`, 'src/output/probe.ts')).toContain('macwarden/capability-boundary');
  });
it.each([['eval', "eval('void 0');", 'no-eval'], ['Function', "new Function('return 0');", 'no-new-func']])(
  'CP-040/B11-meaningful-tests dynamic %s code cannot bypass capabilities', async (_label, code, rule) => {
    expect(await rules(code, 'src/output/probe.ts')).toContain(rule);
  });
