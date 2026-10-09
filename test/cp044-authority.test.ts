import { it } from 'vitest';
import { capabilityProbeControls, weakMapInterceptionControl } from './support/cp044-probes.js';
it('CP-044/B1 audited constructed consumers cannot reveal actual sentinel bytes', capabilityProbeControls, 180000);

it('CP-044/B2 WeakMap interception during built inspect cannot capture credential bytes', weakMapInterceptionControl);
