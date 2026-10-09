// Plain JavaScript so it runs on any Node.js and can explain a version that is
// too old to run the TypeScript lab files directly (type stripping).
const [major, minor, patch] = process.versions.node.split('.').map(Number);
const atLeast = (m, p) => minor > m || (minor === m && patch >= p);
const supported = (major === 22 && atLeast(23, 2)) || (major === 24 && atLeast(18, 1)) || major > 26 || (major === 26 && atLeast(5, 1));
if (!supported) {
  process.stderr.write(`Node.js ${process.versions.node} is not supported: the lab needs 22.23.2 or later on 22, 24.18.1 or later on 24, or 26.5.1 or later.\n`);
  process.exit(1);
}
