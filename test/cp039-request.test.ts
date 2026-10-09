import { expect, it, vi } from 'vitest';
import { Secret } from '../src/secret.js';
import { sentinel } from './support/cp039-audit.js';

const state = vi.hoisted(() => ({ requests: 0 }));
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https')>();
  const request = () => { state.requests++; throw Object.assign(new Error('request creation failed'), { code: 'ECONNRESET' }); };
  return { ...original, request, default: { ...original, request } };
});
it('CP-039/B5-strict-response synchronous request failure leaves zero timers and no delayed exception', async () => {
  vi.useFakeTimers();
  try {
    const { createLndAdapter } = await import('../src/lnd/index.js');
    const lnd = createLndAdapter({ restUrl: 'https://localhost:1', tlsCert: Buffer.from('unused local CA'), macaroon: new Secret(sentinel()) });
    let failure: unknown;
    try { await lnd.getInfo(); } catch (error) { failure = error; }
    expect(failure !== undefined, 'one rejected request').toBe(true);
    expect(state.requests).toBe(1);
    expect(vi.getTimerCount(), 'no request timer survives synchronous failure').toBe(0);
    // Await completion so a delayed exception rejects the test; the utility return value is irrelevant.
    await vi.advanceTimersByTimeAsync(11_000);
    expect(vi.getTimerCount(), 'no delayed request timer remains').toBe(0);
    expect(state.requests).toBe(1);
  } finally { vi.useRealTimers(); }
});
