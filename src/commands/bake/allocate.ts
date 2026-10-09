import { LndError } from '../../errors.js';

const MIN_ROOT_KEY_ID = 1n << 32n;
const MAX_ROOT_KEY_ID = (1n << 63n) - 1n;
const MAX_DRAWS = 16;

export function allocateRootKeyId(
  lndIds: readonly bigint[], registryIds: readonly bigint[], draw: () => bigint,
): bigint {
  const used = new Set([...lndIds, ...registryIds]);
  for (let attempt = 0; attempt < MAX_DRAWS; attempt++) {
    const id = draw();
    if (id >= MIN_ROOT_KEY_ID && id <= MAX_ROOT_KEY_ID && !used.has(id)) return id;
  }
  throw new LndError(5, 'allocate-root-key-id', 'unable to allocate a fresh root key ID');
}
