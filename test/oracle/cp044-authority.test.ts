import { it } from 'vitest';
import { capabilityProbeControls, weakMapInterceptionControl } from '../support/cp044-probes.js';
it('CP-044/capability-ground-truth independently executable probes cannot recover sentinel bytes', async () => {
  await capabilityProbeControls();
  await weakMapInterceptionControl();
}, 180000);
