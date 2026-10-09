import { expect, it } from 'vitest';
import { manifest, validateManifest } from '../helpers/cp034-btcpay.mjs';

it('CP-034/btcpay-source-permissions immutable client inventory agrees with the independent pinned LND permission sources', () => {
  expect(validateManifest()).toBe(manifest);
  expect(manifest.calls).toHaveLength(16);
  expect(manifest.permissions).toHaveLength(16);
  expect(manifest.expectedGrade).toBe('SPEND');
});
