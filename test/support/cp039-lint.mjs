import { ESLint } from 'eslint';
import { join } from 'node:path';

// Load ESLint's config and parser with Node, outside Vitest's module evaluator.
const lint = new ESLint({ cwd: process.cwd() });
await lint.lintText('', { filePath: join(process.cwd(), 'src/output/cp039-boundary-probe.ts') });
process.on('message', async ({ code, site }) => {
  try {
    const [result] = await lint.lintText(code, { filePath: join(process.cwd(), site) });
    process.send({ messages: result.messages });
  } catch {
    process.send({ error: 'CP-039 lint probe failed before returning diagnostics' });
  }
});
process.send({ ready: true });
