import { it } from 'vitest';
import { crashClaimControl, ownershipClaimControls, staleProductLockControl } from '../support/cp047-claim.js';
it('CP-047/claim-process-filesystem independent claim ownership controls and provable stale product recovery', async () => {
  await crashClaimControl();
  await ownershipClaimControls();
  await staleProductLockControl();
});
