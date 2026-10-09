import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { run as revoke } from '../src/commands/revoke.js';
import { run as rotate } from '../src/commands/rotate.js';
import { render } from '../src/output/index.js';
import { declare, entry, fixture, nextId, oldId, register, responseBytes, vector, type Entry, type Fixture } from './helpers/cp038-online.js';

// RL-05 (SPEC Global conventions, 3 inventory): every command inventory prints is pasted by the
// operator, so each one must run as printed (with the same connection and --registry flags).

const bobId = 4294967400n, carolId = 4294967401n, daveId = 4294967402n;
const soon = [{ type: 'time-before', value: '2026-10-07T00:00:00Z', requested: '30d' }];

function credential(id: bigint, label: string, permissions: string[], grade: string, caveats: Entry['caveats'] = []): Entry {
  const bytes = responseBytes(id, permissions) as Buffer;
  return { ...entry(id, label), permissions, grade, caveats, outPath: register(bytes),
    fingerprint: 'fp:' + createHash('sha256').update(bytes).digest('hex').slice(0, 16) };
}

/** Shell words of each `with: <command>` advice, unquoted as POSIX sh or PowerShell would. */
function advice(text: string): string[][] {
  const commands: string[][] = [];
  for (const line of text.split('\n')) {
    let at = line.indexOf('with: ');
    while (at !== -1) {
      const args: string[] = [];
      let i = at + 6, word: string | null = null;
      for (; i < line.length; i++) {
        const c = line[i];
        if (c === "'") {
          let j = i + 1, part = '';
          for (; j < line.length; j++) {
            if (line[j] !== "'") { part += line[j]; continue; }
            if (process.platform === 'win32' && line[j + 1] === "'") { part += "'"; j++; continue; }
            break;
          }
          word = (word ?? '') + part; i = j;
        } else if (c === '"') {
          const j = line.indexOf('"', i + 1); word = (word ?? '') + line.slice(i + 1, j); i = j;
        } else if (c === ' ' || c === ';') {
          if (word !== null) { args.push(word); word = null; }
          if (c === ';') break;
        } else word = (word ?? '') + c;
      }
      if (word !== null) args.push(word);
      commands.push(args);
      at = line.indexOf('with: ', i);
    }
  }
  return commands;
}

async function runPrinted(f: Fixture, args: string[]) {
  expect(args[0]).toBe('macwarden');
  const out = args.indexOf('--out');
  if (out !== -1) declare(args[out + 1]);
  // The operator types what the prompt asks for.
  f.deps.prompt = Object.assign(async (question: string) => /Type (\S+) to (?:confirm|continue)/.exec(question)?.[1] ?? '', { isTTY: true });
  const command = args[1] === 'revoke' ? revoke : args[1] === 'rotate' ? rotate : null;
  expect(command).not.toBeNull();
  return command!([...args.slice(2), ...f.flags], f.deps);
}

it('RL-05/an expired credential whose label is ambiguous (staged rotation) is advised by root key ID, and the command runs', async () => {
  const f = fixture();
  // O expired; its replacement N is staged: both are active with label Alice.
  f.save([{ ...f.old, caveats: [{ type: 'time-before', value: '2026-10-01T00:00:00Z' }] }, f.next]);
  const text = render(await inventory([...f.flags], f.deps), 'text');
  expect(text).toContain(`expired; revoke with: macwarden revoke ${oldId}`);
  const commands = advice(text);
  expect(commands).toEqual([['macwarden', 'revoke', String(oldId)]]);
  expect((await runPrinted(f, commands[0])).error).toBeNull();
  expect(f.lnd.deleted).toEqual([oldId]);
});

it('RL-05/an expiring credential is advised with a rotate command that includes --out, and it runs', async () => {
  const f = fixture();
  f.save([{ ...f.old, caveats: soon }]);
  f.lnd.ids = [0n, oldId];
  const text = render(await inventory([...f.flags], f.deps), 'text');
  const commands = advice(text);
  expect(commands).toHaveLength(1);
  const [args] = commands;
  expect(args.slice(0, 4)).toEqual(['macwarden', 'rotate', 'Alice', '--out']);
  // The default is next to the recorded file, named by label and today's date.
  expect(args[4]).toMatch(/Alice-2026-10-05\.macaroon$/);
  const staged = await runPrinted(f, args);
  expect(staged.error).toBeNull();
  expect(staged.result).toMatchObject({ stage: 'staged' });
  void nextId;
});

it('RL-05/every command a mixed inventory prints runs as printed, and refused rows get none', async () => {
  const f = fixture();
  const invoice = vector('preset-invoice-only').permissions;
  const admin = vector('default-admin').permissions;
  const o = { ...f.old, caveats: [{ type: 'time-before', value: '2026-10-01T00:00:00Z' }] };
  const bob = credential(bobId, 'Bob', invoice, 'RECEIVE', soon);
  const carol = credential(carolId, 'Carol', admin, 'ADMIN', soon);
  // A canary is never rotated (rotate S3 refuses it), so it gets no rotate command.
  const dave = credential(daveId, 'Dave', invoice, 'RECEIVE', [...soon, { type: 'lnd-custom', value: 'guard-0123abcd 00' }]);
  f.save([o, f.next, bob, carol, dave]);
  f.lnd.ids = [0n, oldId, nextId, bobId, carolId, daveId];
  const text = render(await inventory([...f.flags], f.deps), 'text');
  const commands = advice(text);
  expect(commands.map(args => args.slice(0, 3))).toEqual([
    ['macwarden', 'revoke', String(oldId)],
    ['macwarden', 'rotate', 'Bob'],
    ['macwarden', 'rotate', 'Carol'],
  ]);
  expect(commands[2]).toContain('--allow-admin');
  expect(text).toMatch(new RegExp(`^${daveId} .*expires in 1d$`, 'm'));
  for (const args of commands) {
    const result = await runPrinted(f, args);
    expect({ args, error: result.error }).toEqual({ args, error: null });
  }
  expect(f.lnd.deleted).toEqual([oldId]);
  expect(f.lnd.baked).toHaveLength(2);
});
