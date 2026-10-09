import { it } from 'vitest';
import { fullControl } from '../harness/cp050-full.js';

// Synthetic reference controls prove evidence handling only. Actual LND and
// complete Windows/Linux milestone validation remain separate obligations.
it('CP-049/evidence-ground-truth independent negatives and original identities govern evidence', () => {
  fullControl('selective-as-full');
  fullControl('changed-candidate');
  fullControl('complete');
});
