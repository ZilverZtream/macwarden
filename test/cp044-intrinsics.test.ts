import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { sentinel } from './support/cp041-controls.js';

// Hooks installed after the credential module loads must never observe its bytes.
it('CP-044/intrinsics late Buffer.from, subarray and hash hooks never observe container bytes', () => {
  const bytes = sentinel();
  const marker = bytes.subarray(0, 20);
  let observed = false;
  const see = (value: unknown) => {
    if (value instanceof Uint8Array && Buffer.from(value.buffer, value.byteOffset, value.byteLength).includes(marker)) observed = true;
  };
  const originalFrom = Buffer.from;
  const hashPrototype = Object.getPrototypeOf(createHash('sha256')) as { update: (...args: unknown[]) => unknown };
  const originalUpdate = hashPrototype.update;
  Buffer.from = ((...args: Parameters<typeof Buffer.from>) => { see(args[0]); return originalFrom.apply(Buffer, args); }) as typeof Buffer.from;
  hashPrototype.update = function (this: unknown, ...args: unknown[]) { see(args[0]); return originalUpdate.apply(this, args); };
  try {
    const secret = new Secret(bytes);
    expect(secret.fingerprint).toMatch(/^fp:[0-9a-f]{16}$/);
  } finally {
    Buffer.from = originalFrom;
    hashPrototype.update = originalUpdate;
  }
  expect(observed).toBe(false);
});
