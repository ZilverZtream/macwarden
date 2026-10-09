import { it } from 'vitest';
import { crashLeakControl } from './support/cp039-crash.js';

it('CP-039/A3-leak-encodings forced mid-request crash emits exactly one safe exit8 document', crashLeakControl, 25_000);
