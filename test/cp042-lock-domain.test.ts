import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { run as revoke } from '../src/commands/revoke.js';
import { fixture } from './helpers/cp038-online.js';
import { deadProductLock } from './helpers/cp042-lock-process.js';

it.each(['legacy', 'mismatched'] as const)('CP-042/B2-ambiguous-lock-refusal %s ownership domain cannot be inferred from same-host ESRCH', async kind => {
  const f = fixture(); const owner = await deadProductLock(f.registry);
  const recorded = JSON.parse(owner.bytes.toString('utf8')) as Record<string, unknown>;
  const legacy = { pid: recorded.pid, hostname: recorded.hostname, startedAt: recorded.startedAt };
  let changed: Record<string, unknown> = legacy;
  if (kind === 'mismatched') {
    const alter = (value: unknown): unknown => typeof value === 'string' ? 'unverified-other-domain'
      : typeof value === 'number' ? value + 1 : value && typeof value === 'object'
        ? Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, alter(nested)])) : null;
    changed = { ...recorded };
    for (const key of Object.keys(recorded).filter(key => !Object.hasOwn(legacy, key))) changed[key] = alter(recorded[key]);
    // An old format with no ownership-domain evidence is equally unverifiable.
    if (Object.keys(changed).length === Object.keys(legacy).length) changed.processDomain = 'unverified-other-domain';
  }
  const bytes = JSON.stringify(changed); writeFileSync(f.registry + '.lock', bytes);
  const before = readFileSync(f.registry), result = await revoke(['Alice', '--yes', '--break-lock', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'V10' }); expect(result.error?.message).toMatch(/offline/i);
  expect(f.lnd.deleted).toEqual([]); expect(readFileSync(f.registry).equals(before)).toBe(true);
  expect(existsSync(f.registry + '.lock')).toBe(true); expect(readFileSync(f.registry + '.lock', 'utf8')).toBe(bytes);
});
