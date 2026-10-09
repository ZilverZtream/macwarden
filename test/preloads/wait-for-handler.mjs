import { performance } from 'node:perf_hooks';

export function afterHandlerInstalled(event, inject) {
  const before = new Set(process.listeners(event));
  const deadline = performance.now() + 3_000;
  const poll = setInterval(() => {
    if (process.listeners(event).some(listener => !before.has(listener))) {
      clearInterval(poll);
      inject();
    } else if (performance.now() >= deadline) {
      clearInterval(poll);
      throw new Error(`Process handler for ${event} was not installed`);
    }
  }, 5);
}
