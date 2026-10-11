import { it } from 'vitest';
import { crashLeakControl } from './support/cp039-crash.js';

// The control spawns the CLI against a local peer and then runs the leak check over the repository
// and the scratch tree (findLeaks); under a loaded full suite that passed 25 s, so it gets 90 s (as
// the other spawn-plus-leak-check tests do).
it('CP-039/A3-leak-encodings forced mid-request crash emits exactly one safe exit8 document', crashLeakControl, 90_000);
