import { ESLint } from 'eslint';
const [site, encoded] = process.argv.slice(2);
try {
  const code = Buffer.from(encoded, 'base64').toString();
  const [result] = await new ESLint({ cwd: process.cwd() }).lintText(code, { filePath: site });
  const rejected = result.messages.some(m => m.severity === 2 && m.ruleId !== null &&
    !['@typescript-eslint/no-unused-vars','@typescript-eslint/no-explicit-any'].includes(m.ruleId));
  process.stdout.write(JSON.stringify({ rejected }));
} catch { process.exitCode = 2; }
