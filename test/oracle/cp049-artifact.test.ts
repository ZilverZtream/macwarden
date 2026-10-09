import { it } from 'vitest';
import { packedArtifactControl } from '../release/cp049-portable.js';
it('CP-049/artifact-ground-truth actual npm archive retains independent file allowlist bytes and executable installed bin', packedArtifactControl, 30000);
