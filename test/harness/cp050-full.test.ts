import { it } from 'vitest';
import { FULL_CONTROL_TIMEOUT_MS, fullControl } from './cp050-full.js';

const timeout = FULL_CONTROL_TIMEOUT_MS + 30_000;

it('CP-050/B2 full CLI retains complete original reports and independently matching candidate inputs', () => fullControl('complete'), timeout);
it('CP-050/B4 changed candidate inputs cannot reuse earlier full validation identity', () => fullControl('changed-candidate'), timeout);
it('CP-050/B4 passing selective diagnosis cannot become complete validation', () => fullControl('selective-as-full'), timeout);
it('CP-050/B2 committed oracle configuration cannot omit an original oracle file from full validation', () =>
  fullControl('oracle-config-exclusion', process.env.CP050_CONTROL_PRODUCER_ROOT), timeout);
it('CP-050/B2 registered sentinel in metadata fails its leak check and preserves safe JSON evidence', () => fullControl('metadata-leak'), timeout);
