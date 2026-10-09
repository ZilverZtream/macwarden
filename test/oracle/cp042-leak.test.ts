import { readFileSync } from 'node:fs';
import { it } from 'vitest';
import { run as rotate } from '../../src/commands/rotate.js';
import { fixture } from '../helpers/cp038-online.js';
import { render } from '../helpers/render-adversarial.js';
import { noEcho } from '../support/cp041-controls.js';

it('CP-042/leak-check recovery cleanup and registry diagnostics contain no recoverable credential', async () => {
  const f = fixture(); f.lnd.verifyValid = false;
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  for (const path of [f.own, f.old.outPath!]) noEcho(render(result, 'text') + render(result, 'json') + readFileSync(f.registry, 'utf8'), readFileSync(path));
});
