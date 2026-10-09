import { render as productionRender } from '../../src/output/index.js';

// Redaction tests deliberately submit hostile/structurally invalid data at
// the public rendering boundary. This assertion is confined to that boundary.
export function render(value: unknown, mode: 'text' | 'json'): string {
  return productionRender(value as Parameters<typeof productionRender>[0], mode);
}
