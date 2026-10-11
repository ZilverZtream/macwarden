import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, rmSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, relative, resolve, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = fileURLToPath(new URL('../', import.meta.url));
const src = resolve(root, 'src');
const dist = resolve(root, 'dist');
const trustedExports = new Map([
  ['decode/index.js', new Set(['DecodeError', 'macaroonPacketRange', 'macaroonSectionRange', 'parseTimeBefore',
    'canonicalMacaroonForm', 'macaroonEosEnd', 'decodeMacaroon', 'encodeMacaroon', 'addFirstPartyCaveat', 'timeBeforeCondition', 'validMacaroonIdentifier', 'isNwcContainer', 'decodeNwc', 'macaroonId',
    'isL402Identifier', 'isL402Container', 'isL402Macaroon', 'l402RedactionSecret', 'decodeL402Macaroon', 'decodeL402Macaroons',
    'decodeL402', 'l402ChallengeMacaroon', 'L402_MAX_MACAROONS', 'isRuneContainer', 'decodeRune'])],
  ['lnd/index.js', new Set(['createLndAdapter', 'registerMiddleware'])],
  ['commands/bake/write-out.js', new Set(['reserveOut'])],
]);
const key = path => relative(src, path).replaceAll('\\', '/').replace(/\.ts$/, '.js');
// Types that hold raw bytes; no export of a credential consumer may hand one out.
const BYTE_TYPES = new Set(['Buffer', 'NonSharedBuffer', 'Uint8Array', 'Uint8ClampedArray', 'Int8Array', 'Uint16Array',
  'Int16Array', 'Uint32Array', 'Int32Array', 'Float16Array', 'Float32Array', 'Float64Array', 'BigUint64Array',
  'BigInt64Array', 'ArrayBuffer', 'SharedArrayBuffer', 'ArrayBufferLike', 'ArrayBufferView', 'DataView', 'Blob']);
// Reviewed exceptions to the consumer export type rule. A `pure` export works only on bytes
// its caller supplies and must not reference the capability module at all (checked); `paths`
// lists the exact places another export may carry bytes that are not the credential.
const BYTE_SIGNATURE_ALLOWANCE = new Map([
  // Re-encodes caller-supplied macaroon bytes; it never sees a Secret.
  ['decode/index.js:canonicalMacaroonForm', { pure: true }],
  // The intercepted RPC request payload LND forwards to the middleware (never the macaroon,
  // which reaches `decide` as a Secret).
  ['lnd/index.js:registerMiddleware', { paths: ['lnd/index.js:registerMiddleware(decide callback).payload'] }],
]);
// An identifier that names a property rather than referring to a binding.
const propertyName = node => node.parent && node.parent.name === node && (ts.isPropertyAccessExpression(node.parent)
  || ts.isPropertyAssignment(node.parent) || ts.isPropertySignature(node.parent) || ts.isPropertyDeclaration(node.parent)
  || ts.isMethodDeclaration(node.parent) || ts.isMethodSignature(node.parent) || ts.isGetAccessor(node.parent)
  || ts.isSetAccessor(node.parent) || ts.isEnumMember(node.parent));
const files = directory => readdirSync(directory, { withFileTypes: true }).flatMap(item =>
  item.isDirectory() ? files(resolve(directory, item.name)) : item.name.endsWith('.ts') ? [resolve(directory, item.name)] : []);

// Compile the complete, statically resolved production graph into one lexical
// module. Public compatibility facades never export the credential authority.
function closedGraph() {
  const config = ts.readConfigFile(resolve(root, 'tsconfig.json'), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const checker = program.getTypeChecker();
  const errorDeclaration = program.getSourceFiles().filter(file => program.isSourceFileDefaultLibrary(file))
    .flatMap(file => file.statements).find(statement => ts.isInterfaceDeclaration(statement) && statement.name.text === 'Error');
  if (!errorDeclaration) throw new Error('Error type unavailable to the build graph');
  const errorType = checker.getDeclaredTypeOfSymbol(checker.getSymbolAtLocation(errorDeclaration.name));
  const production = files(src).filter(path => key(path) !== 'bin.js');
  // Every compiled module runs inside the runtime's lexical scope. Name the
  // loader, its parameters and every runtime binding after a digest of the
  // production sources, so no source can spell them. Without this, @types/node
  // (or an ambient declaration) type-checks `require('./secret-capability.js')`.
  const digest = createHash('sha256');
  for (const path of production) digest.update(key(path)).update('\0').update(readFileSync(path)).update('\0');
  const scope = `__mw${digest.digest('hex').slice(0, 24)}_`;
  const loaderNames = { require: `${scope}require`, exports: `${scope}exports`, module: `${scope}module` };
  const loaderBindings = new Set(Object.keys(loaderNames));
  // Rename on the emitted CommonJS text, re-parsed: export references are
  // substituted at print time, after any transformer could see them. Production
  // sources contain no such identifier (rejected below), so each one is compiler-generated.
  const renameLoader = code => {
    const emitted = ts.createSourceFile('module.js', code, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    const rename = context => file => {
      const visit = node => {
        if (ts.isPropertyAccessExpression(node))
          return ts.factory.updatePropertyAccessExpression(node, ts.visitNode(node.expression, visit), node.name);
        if (ts.isIdentifier(node) && loaderBindings.has(ts.idText(node)))
          return ts.factory.createIdentifier(loaderNames[ts.idText(node)]);
        return ts.visitEachChild(node, visit, context);
      };
      return ts.visitNode(file, visit);
    };
    const [renamed] = ts.transform(emitted, [rename]).transformed;
    return ts.createPrinter().printFile(renamed);
  };
  const builtins = new Map();
  const modules = [];
  const facades = [];
  for (const path of production) {
    const source = program.getSourceFile(path);
    const id = key(path);
    if (source.isDeclarationFile) throw new Error(`ambient production declaration: ${id}`);
    const visit = node => {
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)
        throw new Error(`non-static production import: ${id}`);
      // The compiled module's loader bindings are not part of the production source language.
      if (ts.isIdentifier(node) && loaderBindings.has(ts.idText(node)))
        throw new Error(`module loader identifier in production source: ${id}`);
      if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference))
        throw new Error(`module loader import in production source: ${id}`);
      // Dynamic code reads the loader's (digest-named) bindings from the stack or runtime.js;
      // only a property name may spell eval or Function.
      if (ts.isIdentifier(node) && ['eval', 'Function'].includes(ts.idText(node)) && !propertyName(node))
        throw new Error(`dynamic code in production source: ${id}`);
      if (ts.canHaveModifiers(node) && ts.getModifiers(node)?.some(item => item.kind === ts.SyntaxKind.DeclareKeyword)
        || ts.isModuleDeclaration(node) && node.flags & ts.NodeFlags.GlobalAugmentation)
        throw new Error(`ambient production declaration: ${id}`);
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
    // Lint enforces the capability boundary and the dynamic-code bans; no source may switch
    // them off. A disable comment naming no rule disables every rule, so it is refused too,
    // as are inline configuration and global declarations.
    for (const [comment] of source.text.matchAll(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g)) {
      const directive = /^(?:\/\/|\/\*)\s*(eslint(?:-disable(?:-next-line|-line)?|-enable|-env)?)(?=\s|\*\/|$)([\s\S]*?)(?:\*\/)?$/.exec(comment)
        ?? /^\/\*\s*(globals?)(?=\s|\*\/)([\s\S]*?)\*\/$/.exec(comment);
      if (!directive) continue;
      const [, kind, rest] = directive;
      const rules = rest.split('--')[0];
      if (!kind.startsWith('eslint-disable') || !rules.trim() || /\b(?:no-eval|no-new-func|no-implied-eval|macwarden\/capability-boundary)\b/.test(rules))
        throw new Error(`lint directive weakening the capability boundary in production source: ${id}`);
    }
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
      // A value is raw when it may hold revealSecret, the capability module or
      // bytes it returned: directly, as a data argument of a platform call or
      // constructor (Buffer.from, new Uint8Array, Array.from...), or returned by
      // a closure, method, accessor or class handed out. Production callees are
      // judged by their own returns, so digests and parsed facts stay clean; a
      // declared boolean/void/null result is clean too. Callback arguments are
      // not followed. Bounded; fails closed.
      const capability = item => key(item.getSourceFile().fileName) === 'secret-capability.js'
        && (ts.isSourceFile(item) || item.name?.getText() === 'revealSecret');
      const data = node => checker.getTypeAtLocation(node).getCallSignatures().length === 0;
      const platform = callee => {
        const symbol = checker.getSymbolAtLocation(callee);
        const actual = symbol?.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
        return !actual?.declarations?.length || actual.declarations.some(item =>
          relative(src, item.getSourceFile().fileName).replaceAll('\\', '/').startsWith('..'));
      };
      const opaque = node => {
        const type = checker.getTypeAtLocation(node);
        return (type.isUnion() ? type.types : [type]).every(part => part.flags
          & (ts.TypeFlags.BooleanLike | ts.TypeFlags.VoidLike | ts.TypeFlags.Null | ts.TypeFlags.Never));
      };
      const raw = new Set();
      // Every later assignment to a binding, so a value written after its declaration is followed.
      const writes = new Map();
      const collectWrites = node => {
        if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
          && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment && ts.isIdentifier(node.left)) {
          const target = checker.getSymbolAtLocation(node.left);
          if (target) writes.set(target, [...writes.get(target) ?? [], node.right]);
        }
        ts.forEachChild(node, collectWrites);
      };
      collectWrites(source);
      let budget = 200_000; // analysis steps per module; real consumers use a few thousand
      const rawValue = (node, seen = new Set()) => {
        if (!node || seen.has(node)) return false;
        if (raw.has(node)) return true;
        if (--budget < 0) throw new Error(`credential return analysis exceeded its bound: ${id}`);
        const next = new Set(seen); next.add(node);
        const any = items => items.some(item => rawValue(item, next));
        const found = (() => {
          if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node)
            || ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node) || ts.isAwaitExpression(node)
            || ts.isSpreadElement(node) || ts.isSpreadAssignment(node) || ts.isYieldExpression(node)) return rawValue(node.expression, next);
          if (ts.isFunctionLike(node)) return node.body ? ts.isBlock(node.body) ? rawReturns(node.body, next) : rawValue(node.body, next) : false;
          if (ts.isClassLike(node)) return node.members.some(member => ts.isPropertyDeclaration(member)
            ? rawValue(member.initializer, next) : ts.isClassStaticBlockDeclaration(member) ? false : rawValue(member, next));
          if (ts.isNewExpression(node)) {
            const symbol = checker.getSymbolAtLocation(node.expression);
            const actual = symbol?.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
            if (actual?.declarations?.some(item => key(item.getSourceFile().fileName) === 'secret-capability.js'
              && item.name?.getText() === 'Secret')) return false;
            return rawValue(node.expression, next) || platform(node.expression) && any([...node.arguments ?? []].filter(data));
          }
          if (ts.isIdentifier(node)) {
            let symbol = ts.isShorthandPropertyAssignment(node.parent) && node.parent.name === node
              ? checker.getShorthandAssignmentValueSymbol(node.parent) : checker.getSymbolAtLocation(node);
            if (symbol?.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
            if (symbol?.declarations?.some(capability)) return true;
            if ((writes.get(symbol) ?? []).some(value => rawValue(value, next))) return true;
            return (symbol?.declarations ?? []).some(item =>
              ts.isVariableDeclaration(item) ? rawValue(item.initializer, next)
                : ts.isFunctionDeclaration(item) || ts.isClassDeclaration(item) ? rawValue(item, next) : false);
          }
          if (ts.isCallExpression(node) || ts.isTaggedTemplateExpression(node)) {
            const callee = ts.isCallExpression(node) ? node.expression : node.tag;
            const args = ts.isCallExpression(node) ? [...node.arguments] : [node.template];
            return rawValue(callee, next) || platform(callee) && !opaque(node) && any(args.filter(data));
          }
          if (ts.isTemplateExpression(node)) return any(node.templateSpans.map(span => span.expression));
          if (ts.isNoSubstitutionTemplateLiteral(node)) return false;
          if (ts.isBinaryExpression(node)) return !opaque(node) && any([node.left, node.right]);
          if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) return rawValue(node.expression, next);
          if (ts.isObjectLiteralExpression(node)) return node.properties.some(item =>
            ts.isPropertyAssignment(item) ? rawValue(item.initializer, next)
              : ts.isShorthandPropertyAssignment(item) ? rawValue(item.name, next) : rawValue(item, next));
          if (ts.isArrayLiteralExpression(node)) return any([...node.elements]);
          if (ts.isConditionalExpression(node)) return any([node.whenTrue, node.whenFalse]);
          return false;
        })();
        if (found) raw.add(node);
        return found;
      };
      const rawReturns = (body, seen) => {
        let found = false;
        const visit = node => {
          if (found) return;
          if (ts.isReturnStatement(node) && rawValue(node.expression, seen)) found = true;
          if (node !== body && ts.isFunctionLike(node)) return;
          ts.forEachChild(node, visit);
        };
        visit(body); return found;
      };
      if (exports.some(item => {
        const actual = item.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(item) : item;
        return actual.declarations?.some(declaration => ts.isFunctionDeclaration(declaration) || ts.isClassDeclaration(declaration)
          ? rawValue(declaration) : ts.isVariableDeclaration(declaration) ? rawValue(declaration.initializer) : false);
      })) throw new Error(`credential authority returned by public consumer: ${id}`);

      // Type rules for the three consumers, so that flows the return analysis cannot follow
      // (callbacks, containers, mutation, exceptions) cannot leave with the bytes either.
      const reject = reason => { throw new Error(`credential consumer rule (${reason}): ${id}:${current ? source.getLineAndCharacterOfPosition(current.getStart(source)).line + 1 : 0}`); };
      let current;
      const loose = type => (type.isUnion() ? type.types : [type])
        .some(part => part.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown | ts.TypeFlags.Never));
      const consumerVisit = node => {
        current = node;
        // (1) revealSecret only as the direct callee of a call, never as a value; no namespace import.
        if (ts.isNamespaceImport(node) && posix.normalize(posix.join(posix.dirname(id), node.parent.parent.moduleSpecifier.text)) === 'secret-capability.js')
          reject('namespace import of the capability');
        if (ts.isIdentifier(node) && !ts.isImportSpecifier(node.parent)) {
          let symbol = checker.getSymbolAtLocation(node);
          if (symbol?.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
          if (symbol?.declarations?.some(capability) && !(ts.isCallExpression(node.parent) && node.parent.expression === node))
            reject('revealSecret used as a value');
        }
        // (2) no any annotation, no assertion to any, unknown or never (a double assertion
        // launders any value into any declared type), and no any-typed value returned.
        if (node.kind === ts.SyntaxKind.AnyKeyword) reject('any type');
        if ((ts.isAsExpression(node) || ts.isTypeAssertionExpression(node))
          && loose(checker.getTypeFromTypeNode(node.type))) reject('assertion to any, unknown or never');
        // A value of type any converts silently to any declared return type.
        if (ts.isReturnStatement(node) && node.expression && checker.getTypeAtLocation(node.expression).flags & ts.TypeFlags.Any)
          reject('any returned');
        // Exceptions carry nothing raw; only a constructed Error-derived value is thrown.
        if (ts.isThrowStatement(node)) {
          const thrown = node.expression;
          if (rawValue(thrown) || ts.isNewExpression(thrown) && [...thrown.arguments ?? []].some(argument => rawValue(argument)))
            reject('credential value thrown');
          // Rethrowing a caught value is allowed: every throw in this file is checked here.
          const caught = ts.isIdentifier(thrown) && checker.getSymbolAtLocation(thrown)?.declarations
            ?.some(item => ts.isVariableDeclaration(item) && ts.isCatchClause(item.parent));
          // A symbol (an internal control-flow marker) carries no data either.
          const thrownType = checker.getTypeAtLocation(thrown);
          if (!caught && !(thrownType.flags & ts.TypeFlags.ESSymbolLike) && !checker.isTypeAssignableTo(thrownType, errorType))
            reject('non-Error thrown');
        }
        ts.forEachChild(node, consumerVisit);
      };
      consumerVisit(source);
      // (3) No exported signature hands out bytes, any or unknown: return types (and what a
      // returned function returns), and what an exported function passes to a callback.
      const violations = [];
      const outward = (type, where, seen = new Set()) => {
        if (!type || seen.has(type)) return;
        seen.add(type);
        if (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) { violations.push({ where, what: 'any or unknown' }); return; }
        if (type.isUnion() || type.isIntersection()) { for (const part of type.types) outward(part, where, seen); return; }
        const symbol = type.aliasSymbol ?? type.getSymbol();
        const name = symbol?.getName();
        if (symbol?.declarations?.some(item => key(item.getSourceFile().fileName) === 'secret-capability.js')) return;
        if (BYTE_TYPES.has(name)) { violations.push({ where, what: name }); return; }
        if (checker.isArrayType(type) || checker.isTupleType(type)
          || ['Promise', 'PromiseLike', 'Map', 'ReadonlyMap', 'Set', 'ReadonlySet', 'Iterable', 'IterableIterator', 'AsyncIterable', 'Generator', 'AsyncGenerator'].includes(name)) {
          for (const argument of checker.getTypeArguments(type) ?? type.aliasTypeArguments ?? []) outward(argument, where, seen);
          return;
        }
        for (const signature of [...type.getCallSignatures(), ...type.getConstructSignatures()]) {
          outward(signature.getReturnType(), `${where}()`, seen);
          for (const parameter of signature.getParameters()) {
            const parameterType = checker.getTypeOfSymbol(parameter);
            for (const part of parameterType.isUnion() ? parameterType.types : [parameterType])
              for (const callback of part.getCallSignatures())
                for (const argument of callback.getParameters()) outward(checker.getTypeOfSymbol(argument), `${where}(${parameter.getName()} callback)`, seen);
          }
        }
        // Members declared in production sources; platform types (Error, Date) are opaque.
        for (const property of checker.getPropertiesOfType(type)) {
          if (!property.declarations?.some(item => !relative(src, item.getSourceFile().fileName).startsWith('..'))) continue;
          outward(checker.getTypeOfSymbol(property), `${where}.${property.getName()}`, seen);
        }
        for (const info of checker.getIndexInfosOfType(type)) outward(info.type, `${where}[]`, seen);
      };
      for (const item of exports) {
        if (BYTE_SIGNATURE_ALLOWANCE.get(`${id}:${item.name}`)?.pure) continue;
        const actual = item.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(item) : item;
        outward(checker.getTypeOfSymbol(actual), `${id}:${item.name}`);
      }
      const allowedPaths = new Set([...BYTE_SIGNATURE_ALLOWANCE.values()].flatMap(entry => entry.paths ?? []));
      const unexpected = violations.filter(item => !allowedPaths.has(item.where));
      if (unexpected.length) throw new Error(`credential consumer export can carry raw data: ${unexpected.slice(0, 5)
        .map(item => `${item.where}: ${item.what}`).join('; ')}`);
      // A pure byte export works only on bytes its caller passed: it never reveals.
      for (const [allowed, entry] of BYTE_SIGNATURE_ALLOWANCE) {
        if (!entry.pure) continue;
        const [file, name] = allowed.split(':');
        if (file !== id) continue;
        const item = exports.find(entry => entry.name === name);
        const actual = item && (item.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(item) : item);
        const declaration = actual?.declarations?.[0];
        if (!declaration || !ts.isFunctionDeclaration(declaration)) throw new Error(`allowed byte export missing: ${allowed}`);
        let reveals = false;
        const inspect = node => {
          if (ts.isIdentifier(node)) {
            let symbol = checker.getSymbolAtLocation(node);
            if (symbol?.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
            if (symbol?.declarations?.some(item => key(item.getSourceFile().fileName) === 'secret-capability.js')) reveals = true;
          }
          ts.forEachChild(node, inspect);
        };
        inspect(declaration);
        if (reveals) throw new Error(`allowed byte export touches the capability: ${allowed}`);
      }
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
    code = renameLoader(code);
    modules.push(`${JSON.stringify(id)}: (${loaderNames.module}, ${loaderNames.exports}, ${loaderNames.require}) => {\n${code}\n}`);
    if (id !== 'secret-capability.js') {
      const index = facades.length;
      facades.push({ id, index, names: exports.map(item => item.name) });
    }
  }
  // Runtime bindings share the factories' lexical scope; they carry the digest prefix too.
  const [builtinsName, factoriesName, cacheName, snapshotName, loadName] =
    ['builtins', 'factories', 'cache', 'snapshot', 'load'].map(name => scope + name);
  const imports = [...builtins].map(([name, alias]) => `import * as ${scope}${alias} from ${JSON.stringify(name)};`).join('\n');
  const builtinMap = [...builtins].map(([name, alias]) => `${JSON.stringify(name)}: ${scope}${alias}`).join(',');
  const snapshot = readFileSync(resolve(src, 'grade/lnd-permissions.json'), 'utf8');
  const runtime = `${imports}\nconst ${builtinsName} = {${builtinMap}};\nconst ${factoriesName} = {${modules.join(',\n')}};\n` +
    `const ${cacheName} = {__proto__:null};\nconst ${snapshotName} = ${snapshot};\n` +
    `function ${loadName}(id) { if (id === 'grade/lnd-permissions.json') return ${snapshotName}; if (${cacheName}[id]) return ${cacheName}[id].exports;
      const factory = ${factoriesName}[id]; if (!factory) throw new Error('unresolved compiled module');
      const module = {exports:{__proto__:null}}; ${cacheName}[id] = module;
      factory(module, module.exports, name => { if (name.startsWith('node:')) return ${builtinsName}[name];
        const parts = id.split('/'); parts.pop(); for (const part of name.split('/')) {
          if (part === '..') parts.pop(); else if (part !== '.') parts.push(part);
        } return ${loadName}(parts.join('/')); }); return module.exports; }\n` +
    facades.flatMap(({id,index,names}) => names.map(name =>
      `export const ${scope}api${index}_${name} = ${loadName}(${JSON.stringify(id)}).${name};`)).join('\n');
  writeFileSync(resolve(dist, 'runtime.js'), runtime);
  for (const {id,index,names} of facades) {
    const path = resolve(dist, id);
    const modulePath = relative(dirname(path), resolve(dist, 'runtime.js')).replaceAll('\\', '/');
    const exports = names.map(name => `${scope}api${index}_${name} as ${name}`).join(', ');
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
