import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

let serializationCalls = 0;

class SerializingArray extends Array<number> {
  toJSON(): number[] {
    serializationCalls++;
    return [901, 902];
  }
}

class NestedArray extends SerializingArray {}

function hookedArray(): NestedArray {
  return new NestedArray(11, 22);
}

function alteredPrototypeArray(): number[] {
  const values = [31, 32];
  Object.setPrototypeOf(values, Object.create(Array.prototype));
  return values;
}

function envelope(value: unknown) {
  return { schema: 1 as const, command: 'arraypoison', ok: true, warnings: [],
    result: { nested: { values: value } }, error: null };
}

vi.mock('../src/commands/handlers.js', () => ({ handlers: {
  arraypoison: async () => ({ code: 0, warnings: [],
    result: { nested: { values: hookedArray() } } }),
} }));

import { main } from '../src/cli.js';

for (const mode of ['text', 'json'] as const) {
  it(`CP-037/A9-nonplain-output rejects nested Array subclass before ${mode} serialization`, async () => {
    const { render } = await import('./helpers/render-adversarial.js');
    serializationCalls = 0;
    let rejected = false;
    try { render(envelope(hookedArray()), mode); }
    catch { rejected = true; }
    expect(serializationCalls, 'inherited toJSON must not run').toBe(0);
    expect(rejected, 'the non-plain array must be refused').toBe(true);
  });

  it(`CP-037/A9-nonplain-output rejects a plain Array with a replaced prototype in ${mode}`, async () => {
    const { render } = await import('./helpers/render-adversarial.js');
    expect(() => render(envelope(alteredPrototypeArray()), mode)).toThrow();
  });

  it(`CP-037/A9-nonplain-output returns the internal error for a nested Array subclass in ${mode}`, async () => {
    serializationCalls = 0;
    const observed = await captureMain(main, ['arraypoison', ...(mode === 'json' ? ['--json'] : [])]);
    expect(serializationCalls, 'the command must not invoke inherited toJSON').toBe(0);
    expect(observed.code).toBe(8);
    if (mode === 'json') {
      expect(observed.stderr).toBe('');
      const document = JSON.parse(observed.stdout) as Record<string, unknown>;
      expect(document).toEqual({ schema: 1, command: 'arraypoison', ok: false,
        warnings: [], result: null,
        error: { code: 8, step: 'internal', message: expect.any(String) } });
      expect(observed.stdout).not.toContain('901');
    } else {
      expect(observed.stdout).toBe('');
      expect(observed.stderr).toMatch(/^error: internal[^\r\n]*\r?\n$/);
    }
  });
}

it('CP-037/A9-nonplain-output accepts a nested plain Array in both render modes', async () => {
  const { render } = await import('./helpers/render-adversarial.js');
  const plain = envelope([41, 42]);
  expect(JSON.parse(render(plain, 'json'))).toEqual(plain);
  expect(render(plain, 'text')).toContain('41');
  expect(render(plain, 'text')).toContain('42');
});
