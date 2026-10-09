import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

const state = vi.hoisted(() => ({ lookups: 0, dispatches: 0 }));
vi.mock('../src/commands/handlers.js', () => ({ handlers: new Proxy({
  scan: async () => { state.dispatches++;
    return { schema: 1, command: 'scan', ok: true, warnings: [], error: null, exitCode: 1,
      result: { findings: [], skipped: [], summary: { filesScanned: 0, filesSkipped: 0, dropped: 0, ignored: 0, findings: 0,
        distinct: 0, byGrade: { ADMIN: 0, SPEND: 0, OPERATE: 0, RECEIVE: 0, READ: 0, UNASSESSED: 0, NWC: 0, UNDECODABLE: 0, L402: 0 } },
        failOn: { threshold: 'SPEND', count: 1 } } };
  },
}, { get(target, key, receiver) { if (key === 'scan') state.lookups++; return Reflect.get(target, key, receiver); } }) }));
import { main } from '../src/cli.js';
it('CP-038/B12-dispatch scan preserves fail-on exit 1 with one lookup and one JSON document', async () => {
  state.lookups = 0; state.dispatches = 0;
  const result = await captureMain(main, ['scan', '--json']);
  expect(result.code).toBe(1); expect(result.exitCalls).toBe(0);
  expect(JSON.parse(result.stdout)).toMatchObject({ ok: true, error: null, command: 'scan' });
  expect(JSON.parse(result.stdout)).not.toHaveProperty('exitCode');
  expect(result.stderr).toBe(''); expect(state.dispatches).toBe(1); expect(state.lookups).toBe(1);
});
