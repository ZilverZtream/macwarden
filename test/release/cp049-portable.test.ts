import { it } from 'vitest';
import { packedArtifactControl } from './cp049-portable.js';
it('CP-049/B1 actual npm packed files and installed bin survive Windows GNU tar and unprivileged Linux extraction', packedArtifactControl);
