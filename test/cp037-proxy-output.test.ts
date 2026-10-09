import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

const fixture = vi.hoisted(() => {
  const traps: string[] = [];
  let kind: 'object' | 'array' = 'object';

  function make(valueKind: 'object' | 'array'): object {
    const target = valueKind === 'array' ? ['ordinary'] : { ordinary: 'value' };
    return new Proxy(target, {
      get(value, key, receiver) {
        traps.push(`get:${String(key)}`);
        if (key === 'toJSON') return () => ({ unchecked: 'synthetic-output' });
        return Reflect.get(value, key, receiver);
      },
      ownKeys(value) {
        traps.push('ownKeys');
        return Reflect.ownKeys(value);
      },
      getOwnPropertyDescriptor(value, key) {
        traps.push(`descriptor:${String(key)}`);
        return Reflect.getOwnPropertyDescriptor(value, key);
      },
      getPrototypeOf(value) {
        traps.push('getPrototypeOf');
        return Reflect.getPrototypeOf(value);
      },
      has(value, key) {
        traps.push(`has:${String(key)}`);
        return Reflect.has(value, key);
      },
    });
  }

  return { traps, make, get kind() { return kind; }, set kind(value: 'object' | 'array') { kind = value; } };
});

vi.mock('../src/commands/handlers.js', () => ({ handlers: {
  proxyprobe: async () => ({ code: 0, warnings: [],
    result: { nested: { value: fixture.make(fixture.kind) } } }),
} }));

import { main } from '../src/cli.js';

function envelope(value: unknown) {
  return { schema: 1 as const, command: 'proxyprobe', ok: true, warnings: [],
    result: { nested: { value } }, error: null };
}

for (const kind of ['object', 'array'] as const) {
  for (const mode of ['text', 'json'] as const) {
    it(`CP-037/A9-nonplain-output rejects a nested ${kind} Proxy before ${mode} traps run`, async () => {
      const { render } = await import('./helpers/render-adversarial.js');
      fixture.traps.length = 0;
      let rejected = false;
      try { render(envelope(fixture.make(kind)), mode); }
      catch { rejected = true; }
      expect(fixture.traps, 'no Proxy trap may run before rejection').toEqual([]);
      expect(rejected, 'the nested Proxy must be rejected').toBe(true);
    });

    it(`CP-037/A9-nonplain-output maps a nested ${kind} Proxy to the ${mode} internal error`, async () => {
      fixture.kind = kind;
      fixture.traps.length = 0;
      const observed = await captureMain(main, ['proxyprobe', ...(mode === 'json' ? ['--json'] : [])]);
      expect(fixture.traps, 'the command must reject before touching Proxy traps').toEqual([]);
      expect(observed.code).toBe(8);
      expect(observed.exitCalls).toBe(0);
      if (mode === 'json') {
        expect(observed.stderr).toBe('');
        expect(JSON.parse(observed.stdout)).toEqual({
          schema: 1, command: 'proxyprobe', ok: false, warnings: [], result: null,
          error: { code: 8, step: 'internal', message: expect.any(String) },
        });
        expect(observed.stdout).not.toContain('synthetic-output');
      } else {
        expect(observed.stdout).toBe('');
        expect(observed.stderr).toMatch(/^error: internal[^\r\n]*\r?\n$/);
        expect(observed.stderr).not.toContain('synthetic-output');
      }
    });
  }
}

it('CP-037/A9-nonplain-output accepts nested plain objects and arrays in both modes', async () => {
  const { render } = await import('./helpers/render-adversarial.js');
  for (const value of [{ ordinary: 'value' }, ['ordinary']]) {
    const plain = envelope(value);
    expect(JSON.parse(render(plain, 'json'))).toEqual(plain);
    expect(render(plain, 'text')).toContain(Array.isArray(value) ? 'ordinary' : 'value');
  }
});
