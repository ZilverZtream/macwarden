// Collects (never runs) every test of one Vitest configuration and writes the names the
// JSON reporter will give them: { file, fullName, title } per test, fullName being the
// ancestor suite titles and the title joined by single spaces, exactly as the reporter
// builds it. Full validation uses this to reject duplicate names before any test phase.
// Usage: node scripts/collect-test-names.mjs <config> <output.json>
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createVitest } from 'vitest/node';

const [config, output] = process.argv.slice(2);
if (!config || !output) { process.stderr.write('usage: collect-test-names <config> <output.json>\n'); process.exit(2); }
const vitest = await createVitest('test', { config: resolve(config), watch: false, run: true });
try {
  const { testModules, unhandledErrors } = await vitest.collect([], { staticParse: false });
  if (unhandledErrors.length) throw new Error(`${unhandledErrors.length} unhandled collection errors`);
  const tests = [];
  for (const module of testModules) {
    if (module.task.result?.state === 'fail') throw new Error('a test file failed to collect');
    for (const test of module.children.allTests()) {
      // The reporter walks task.suite upward; module-level tests have no ancestors.
      const ancestors = [];
      for (let suite = test.task.suite; suite && suite !== module.task; suite = suite.suite) ancestors.unshift(suite.name);
      const title = test.task.name;
      tests.push({ file: module.moduleId, title, fullName: title ? [...ancestors, title].join(' ') : ancestors.join(' ') });
    }
  }
  writeFileSync(output, JSON.stringify(tests));
} finally {
  await vitest.close();
}
process.exit(0);
