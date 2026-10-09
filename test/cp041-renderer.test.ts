import { afterAll, beforeAll, expect, it } from 'vitest';
import { error, render, type OutputResult } from '../src/output/index.js';
import { fingerprint, noEcho, peerForms, sentinel } from './support/cp041-controls.js';
import { peer as createPeer, pubkey } from './support/cp041-peer.js';

let peer: Awaited<ReturnType<typeof createPeer>>;
beforeAll(async () => { peer = await createPeer(); });
afterAll(async () => { await peer?.close(); });
for (const form of peerForms) {
  it(`CP-041/B3-renderer-encoded-peer-echo suppresses ${form.name} results errors and warnings`, () => {
    const bytes = sentinel(), echo = String(form.encode(bytes));
    const message = `safe-left ${echo} safe-right`;
    const good: OutputResult = { schema: 1, command: 'inventory', ok: true, display: { now: Date.parse('2026-10-06T00:00:00Z') }, warnings: [{ code: 'snapshot-drift', message }],
      result: { node: { pubkey, alias: message, version: '0.21.4-beta', network: 'regtest' }, rootKeys: [] }, error: null };
    const bad: OutputResult = { schema: 1, command: 'inventory', ok: false, warnings: [], result: null,
      error: { code: 5, step: 'N4', message } };
    for (const value of [good, bad]) for (const mode of ['text', 'json'] as const) {
      const rendered = render(value, mode); noEcho(rendered, bytes);
      expect.soft(rendered.includes('[redacted]'), 'redaction occurs through actual renderer').toBe(true);
      expect.soft(rendered.includes('safe-left ') && rendered.includes(' safe-right'), 'safe surrounding context retained').toBe(true);
      if (mode === 'json') { const doc = JSON.parse(rendered);
        expect(doc.schema === 1 && doc.command === 'inventory' && doc.ok === value.ok, 'single correct JSON envelope').toBe(true); }
    }
    noEcho(error('N4', message), bytes);
  });
  it(`CP-041/B3-renderer-encoded-peer-echo built inventory suppresses ${form.name} over real HTTPS`, async () => {
    const bytes = sentinel(); peer.state.echo = `safe-left ${String(form.encode(bytes))} safe-right`;
    // 0x byte-array text exceeds the adapter's documented 256-character alias limit;
    // exercise that representation in its unrestricted error-message path instead.
    for (const failure of form.name === 'comma 0x array' ? [true] : [false, true]) for (const mode of ['text', 'json'] as const) {
      peer.state.failure = failure; const observed = await peer.inventory(mode);
      expect.soft(observed.code, 'built inventory observed exit').toBe(failure ? 5 : 0);
      noEcho(observed.stdout + observed.stderr, bytes);
      if (!failure) expect.soft((observed.stdout + observed.stderr).includes('safe-left ') &&
        (observed.stdout + observed.stderr).includes(' safe-right'), 'peer context survives real adapter and CLI').toBe(true);
      if (mode === 'json') {
        const doc = JSON.parse(observed.stdout);
        expect(doc.ok === !failure && doc.command === 'inventory', 'one expected inventory envelope').toBe(true);
        if (failure) expect(doc.error.code === 5 && doc.error.step === 'N4', 'safe adapter error classification').toBe(true);
        expect(observed.stderr.length).toBe(0);
      }
      expect(peer.state.calls[0]).toBe('/v1/getinfo');
    }
  });
}
it('CP-041/B3-renderer-encoded-peer-echo preserves bounded benign look-alikes fingerprints and terminal escaping', () => {
  const message = `safe-left [0x02,0x01] 2;1;3 ab_cd ef.01 ${fingerprint(sentinel())} \u001b safe-right`;
  const envelope: OutputResult = { schema: 1, command: 'inventory', ok: false, warnings: [], result: null,
    error: { code: 5, step: 'N4', message } };
  expect(JSON.parse(render(envelope, 'json')).error.message === message, 'benign bounded data retained').toBe(true);
  const text = render(envelope, 'text'); expect(text.includes('\\x1b') && !text.includes('\u001b')).toBe(true);
  expect(text.includes(fingerprint(sentinel()))).toBe(true);
});
