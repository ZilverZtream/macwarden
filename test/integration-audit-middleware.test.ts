import { expect, it } from 'vitest';
import { macaroonId } from '../src/decode/index.js';
import { MAX_MACAROON_BYTES, OVERSIZED_MACAROON_PREFIX_BYTES, decodeMiddlewareRequest } from '../src/lnd/middleware-proto.js';
import { Secret } from '../src/secret.js';
import { middlewareRequest } from './helpers/payment-proto.js';
import { identityOf, vector } from './helpers/payment-journal.js';

// Audit 1.4.0: a macaroon over MAX_MACAROON_BYTES (padded by the caller; LND still accepts it) kept
// nothing, so watch and the payment journal recorded id:undecodable for a credential whose identity
// is in its first bytes. Only a bounded prefix is passed on, as a view of the frame.
it('an oversized intercepted macaroon keeps a bounded prefix that yields its header identity', () => {
  const admin = vector('default-admin');
  // Synthetic padding after a real header: past the limit by one byte.
  const padded = Buffer.concat([admin, Buffer.alloc(MAX_MACAROON_BYTES + 1 - admin.length, 0x61)]);
  const frame = middlewareRequest({ method: '/routerrpc.Router/SendPaymentV2', serialized: Buffer.alloc(1), macaroon: padded });
  const request = decodeMiddlewareRequest(frame);
  expect(request.oversizedMacaroon).toBe(true);
  expect(request.rawMacaroon.length).toBe(OVERSIZED_MACAROON_PREFIX_BYTES);
  expect(OVERSIZED_MACAROON_PREFIX_BYTES).toBeLessThan(MAX_MACAROON_BYTES);
  expect(request.rawMacaroon.equals(padded.subarray(0, OVERSIZED_MACAROON_PREFIX_BYTES))).toBe(true);
  // A view into the frame, not a caller-sized copy.
  expect(request.rawMacaroon.buffer).toBe(frame.buffer);
  expect(macaroonId(new Secret(request.rawMacaroon)).id).toBe(identityOf(admin));

  // At the limit nothing changes: the whole macaroon is passed on and not flagged.
  const atLimit = Buffer.concat([admin, Buffer.alloc(MAX_MACAROON_BYTES - admin.length, 0x61)]);
  const kept = decodeMiddlewareRequest(middlewareRequest({ method: '/routerrpc.Router/SendPaymentV2', serialized: Buffer.alloc(1), macaroon: atLimit }));
  expect({ length: kept.rawMacaroon.length, oversized: kept.oversizedMacaroon }).toEqual({ length: MAX_MACAROON_BYTES, oversized: false });
});
