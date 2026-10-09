import { openRegistry } from '../../src/registry/index.js';
// Create the ownership record through the product, never fabricate its domain.
try {
  const view = await openRegistry(process.argv[2]);
  await view.lock();
  process.send?.({ kind: 'locked' });
  process.on('message', () => {});
} catch (error) {
  process.send?.({ kind: 'failed', category: error?.name });
  process.exitCode = 1;
  process.disconnect?.();
}
