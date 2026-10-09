import { it, expect } from 'vitest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { findLeaks } from '../../scripts/leak-check.mjs';
import { commandLeakControl, commandNames } from '../support/cp039-commands.js';
import { crashLeakControl } from '../support/cp039-crash.js';
import { auditEncodings, repo, scratch, sentinel, sentinelList } from '../support/cp039-audit.js';

it('CP-039/leak-check live captures all six commands and a forced request crash with independent positive controls', async () => {
  for (const command of commandNames) await commandLeakControl(command);
  await crashLeakControl();
  await scratch(dir => {
    for (const [name, value] of auditEncodings(sentinel())) {
      const path = join(dir, 'independent-capture.txt'); writeFileSync(path, value);
      expect.soft(findLeaks({ sentinels: sentinelList, root: repo, paths: [path] }) !== null,
        `${name} independent file leak control`).toBe(true);
      if (typeof value === 'string') expect.soft(findLeaks({ sentinels: sentinelList, root: repo, commandOutput: value }) !== null,
        `${name} independent command-output leak control`).toBe(true);
    }
  });
}, 60_000);
