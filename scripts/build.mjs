import { copyFileSync, mkdirSync, rmSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, relative, resolve, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = fileURLToPath(new URL('../', import.meta.url));
const src = resolve(root, 'src');
const dist = resolve(root, 'dist');
const trustedExports = new Map([
  ['decode/index.js', new Set(['DecodeError', 'macaroonPacketRange', 'macaroonSectionRange', 'parseTimeBefore',
    'canonicalMacaroonForm', 'macaroonEosEnd', 'decodeMacaroon', 'encodeMacaroon', 'addFirstPartyCaveat', 'timeBeforeCondition', 'validMacaroonIdentifier', 'isNwcContainer', 'decodeNwc', 'macaroonId'])],
  ['lnd/index.js', new Set(['createLndAdapter', 'registerMiddleware'])],
  ['commands/bake/write-out.js', new Set(['reserveOut'])],
]);
const key = path => relative(src, path).replaceAll('\\', '/').replace(/\.ts$/, '.js');
const files = directory => readdirSync(directory, { withFileTypes: true }).flatMap(item =>
  item.isDirectory() ? files(resolve(directory, item.name)) : item.name.endsWith('.ts') ? [resolve(directory, item.name)] : []);

// Compile the complete, statically resolved production graph into one lexical
// module. Public compatibility facades never export the credential authority.
function closedGraph() {
  const config = ts.readConfigFile(resolve(root, 'tsconfig.json'), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const checker = program.getTypeChecker();
  const production = files(src).filter(path => key(path) !== 'bin.js');
  const builtins = new Map();
  const modules = [];
  const facades = [];
  for (const path of production) {
    const source = program.getSourceFile(path);
    const id = key(path);
    const visit = node => {
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)
        throw new Error(`non-static production import: ${id}`);
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
        if (!ts.isStringLiteral(node.moduleSpecifier)) throw new Error(`unresolved production import: ${id}`);
        const name = node.moduleSpecifier.text;
        if (name.startsWith('node:')) { if (!builtins.has(name)) builtins.set(name, `builtin${builtins.size}`); }
        else if (!name.startsWith('.')) throw new Error(`external production import: ${id}`);
        else {
          const target = posix.normalize(posix.join(posix.dirname(id), name));
          if (target === 'secret-capability.js') {
            const facade = id === 'secret.js' && ts.isExportDeclaration(node)
              && node.exportClause && ts.isNamedExports(node.exportClause)
              && node.exportClause.elements.every(item => item.name.text === 'Secret' && (item.propertyName?.text ?? item.name.text) === 'Secret');
            const consumer = ['decode/index.js', 'lnd/index.js', 'commands/bake/write-out.js'].includes(id)
              && ts.isImportDeclaration(node);
            if (!facade && !consumer) throw new Error(`unauthorized credential graph edge: ${id}`);
          }
          if (!production.some(file => key(file) === target) && !target.endsWith('.json'))
            throw new Error(`unresolved production graph edge: ${id}`);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
    const symbol = checker.getSymbolAtLocation(source);
    const exports = checker.getExportsOfModule(symbol).filter(item => {
      const actual = item.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(item) : item;
      return Boolean(actual.flags & ts.SymbolFlags.Value);
    });
    const approved = trustedExports.get(id);
    if (approved && exports.some(item => !approved.has(item.name)))
      throw new Error(`unapproved credential consumer export: ${id}`);
    // Follow value aliases using compiler symbols rather than identifier spelling.
    const authority = (symbol, seen = new Set()) => {
      if (!symbol || seen.has(symbol)) return false;
      seen.add(symbol);
      if (symbol.flags & ts.SymbolFlags.Alias) return authority(checker.getAliasedSymbol(symbol), seen);
      for (const declaration of symbol.declarations ?? []) {
        if (ts.isSourceFile(declaration) && key(declaration.fileName) === 'secret-capability.js') return true;
        if (key(declaration.getSourceFile().fileName) === 'secret-capability.js'
          && declaration.name?.getText() === 'revealSecret') return true;
        if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
          let found = false;
          const inspect = node => {
            if (ts.isIdentifier(node) && authority(checker.getSymbolAtLocation(node), seen)) found = true;
            ts.forEachChild(node, inspect);
          };
          inspect(declaration.initializer);
          if (found) return true;
        }
      }
      return false;
    };
    if (id !== 'secret-capability.js' && exports.some(item => authority(item)))
      throw new Error(`credential authority exported: ${id}`);
    if (approved) {
      // Inspect values returned from approved functions too. A function body
      // cannot hide a raw accessor behind an existing public export name.
      const rawValue = (node, seen = new Set()) => {
        if (!node || seen.has(node)) return false;
        const next = new Set(seen); next.add(node);
        if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)
          || ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node)) return rawValue(node.expression, next);
        if (ts.isNewExpression(node)) {
          const symbol = checker.getSymbolAtLocation(node.expression);
          const actual = symbol?.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
          if (actual?.declarations?.some(item => key(item.getSourceFile().fileName) === 'secret-capability.js'
            && item.name?.getText() === 'Secret')) return false;
        }
        if (ts.isIdentifier(node)) {
          let symbol = checker.getSymbolAtLocation(node);
          if (symbol?.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
          if (symbol?.declarations?.some(item => key(item.getSourceFile().fileName) === 'secret-capability.js'
            && item.name?.getText() === 'revealSecret')) return true;
          return (symbol?.declarations ?? []).some(item =>
            ts.isVariableDeclaration(item) ? rawValue(item.initializer, next)
              : ts.isFunctionDeclaration(item) && item.body ? rawReturns(item.body, next) : false);
        }
        if (ts.isCallExpression(node)) return rawValue(node.expression, next);
        if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) return rawValue(node.expression, next);
        if (ts.isObjectLiteralExpression(node)) return node.properties.some(item =>
          ts.isPropertyAssignment(item) ? rawValue(item.initializer, next)
            : ts.isShorthandPropertyAssignment(item) ? rawValue(item.name, next) : false);
        if (ts.isArrayLiteralExpression(node)) return node.elements.some(item => rawValue(item, next));
        if (ts.isConditionalExpression(node)) return rawValue(node.whenTrue, next) || rawValue(node.whenFalse, next);
        return false;
      };
      const rawReturns = (body, seen) => {
        let found = false;
        const visit = node => {
          if (ts.isReturnStatement(node) && rawValue(node.expression, seen)) found = true;
          if (node !== body && ts.isFunctionLike(node)) return;
          ts.forEachChild(node, visit);
        };
        visit(body); return found;
      };
      if (exports.some(item => {
        const actual = item.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(item) : item;
        return actual.declarations?.some(declaration => ts.isFunctionDeclaration(declaration)
          && declaration.body && rawReturns(declaration.body, new Set()));
      })) throw new Error(`credential authority returned by public consumer: ${id}`);
    }
    let code = ts.transpileModule(readFileSync(path, 'utf8'), { compilerOptions: {
      target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true,
    } }).outputText;
    // Export objects are private authority containers. Never hand them to a
    // replaceable global intrinsic, including compiler-generated interop code.
    code = code.replace('Object.defineProperty(exports, "__esModule", { value: true });', 'exports.__esModule = true;');
    code = code.replace(/Object\.defineProperty\(exports, "([A-Za-z_$][\w$]*)", \{ enumerable: true, get: function \(\) \{ return ([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*); \} \}\);/g,
      (_, name, value) => `module.exports = exports = { __proto__: null, ...exports, get ${name}() { return ${value}; } };`);
    if (code.includes('Object.defineProperty(exports,')) throw new Error(`unsupported compiled export shape: ${id}`);
    modules.push(`${JSON.stringify(id)}: (module, exports, require) => {\n${code}\n}`);
    if (id !== 'secret-capability.js') {
      const index = facades.length;
      facades.push({ id, index, names: exports.map(item => item.name) });
    }
  }
  const imports = [...builtins].map(([name, alias]) => `import * as ${alias} from ${JSON.stringify(name)};`).join('\n');
  const builtinMap = [...builtins].map(([name, alias]) => `${JSON.stringify(name)}: ${alias}`).join(',');
  const snapshot = readFileSync(resolve(src, 'grade/lnd-permissions.json'), 'utf8');
  const runtime = `${imports}\nconst builtins = {${builtinMap}};\nconst factories = {${modules.join(',\n')}};\n` +
    `const cache = {__proto__:null};\nconst snapshot = ${snapshot};\n` +
    `function load(id) { if (id === 'grade/lnd-permissions.json') return snapshot; if (cache[id]) return cache[id].exports;
      const factory = factories[id]; if (!factory) throw new Error('unresolved compiled module');
      const module = {exports:{__proto__:null}}; cache[id] = module;
      factory(module, module.exports, name => { if (name.startsWith('node:')) return builtins[name];
        const parts = id.split('/'); parts.pop(); for (const part of name.split('/')) {
          if (part === '..') parts.pop(); else if (part !== '.') parts.push(part);
        } return load(parts.join('/')); }); return module.exports; }\n` +
    facades.flatMap(({id,index,names}) => names.map(name =>
      `export const api${index}_${name} = load(${JSON.stringify(id)}).${name};`)).join('\n');
  writeFileSync(resolve(dist, 'runtime.js'), runtime);
  for (const {id,index,names} of facades) {
    const path = resolve(dist, id);
    const modulePath = relative(dirname(path), resolve(dist, 'runtime.js')).replaceAll('\\', '/');
    const exports = names.map(name => `api${index}_${name} as ${name}`).join(', ');
    writeFileSync(path, `export {${exports}} from ${JSON.stringify(modulePath.startsWith('.') ? modulePath : './' + modulePath)};\n`);
  }
  writeFileSync(resolve(dist, 'secret-capability.js'), "export { Secret } from './secret.js';\n");
}

if (process.argv[2] === '--copy-permissions') {
  closedGraph();
  mkdirSync(new URL('../dist/grade/', import.meta.url), { recursive: true });
  copyFileSync(
    new URL('../src/grade/lnd-permissions.json', import.meta.url),
    new URL('../dist/grade/lnd-permissions.json', import.meta.url),
  );
} else {
  rmSync(new URL('../dist/', import.meta.url), { recursive: true, force: true });
}
