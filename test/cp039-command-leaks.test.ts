import { it } from 'vitest';
import { commandLeakControl, commandNames } from './support/cp039-commands.js';

for (const command of commandNames) {
  it(`CP-039/A3-leak-encodings ${command} captures every output and registered runtime credential`,
    async () => commandLeakControl(command), 30_000); // owner-approved 2026-10-07: spawns the CLI per encoding; >5 s under full-suite load
}
