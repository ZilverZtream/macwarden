import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import { resolve, dirname } from 'node:path';

// Credential access is an import capability. Secret instances expose no bytes.
const capabilityBoundary = {
  meta: { type: 'problem', messages: { forbidden: 'Capability is restricted to its approved module boundary.' } },
  create(context) {
    const file = context.filename.replaceAll('\\', '/');
    const publicFacade = /\/src\/secret\.ts$/.test(file);
    const credential = /\/src\/(?:decode\/|lnd\/|commands\/bake\/write-out\.ts$|secret\.ts$|secret-capability\.ts$)/.test(file);
    const network = /\/src\/lnd\//.test(file);
    const ownershipQuery = /\/src\/registry\/process-domain\.ts$/.test(file);
    const acl = /\/src\/commands\/bake\/write-out\.ts$/.test(file);
    const gitHistory = /\/src\/scan\/git-history\.ts$/.test(file) || /\/src\/watch\/alert\.ts$/.test(file);
    const writerCaller = /\/src\/commands\/(?:bake\/index|rotate|attenuate|inventory)\.ts$/i.test(file);
    const builtins = new Set(['crypto', 'util', 'fs', 'fs/promises', 'path', 'os', 'stream', 'readline', 'async_hooks']);
    const forbiddenGlobals = new Set(['eval', 'Function', 'Reflect', 'fetch', 'WebSocket', 'EventSource', 'XMLHttpRequest',
      'Worker', 'SharedWorker', 'require', 'console']);
    const report = node => context.report({ node, messageId: 'forbidden' });
    // Transparent wrappers preserve the value; charge each to the caller's budget.
    // Classifiers must treat a negative shared budget as restricted provenance.
    const transparentExpression = (node, budget) => {
      while (node && ['TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression',
        'TSSatisfiesExpression', 'TSInstantiationExpression', 'ChainExpression', 'ParenthesizedExpression'].includes(node.type)) {
        if (--budget.remaining < 0) return undefined;
        node = node.expression;
      }
      return node;
    };
    // Resolve literals, const identifiers and string concatenation without executing source.
    // Bound both traversal and strings; unresolved data keys remain permitted.
    const constantKey = (node, budget = { remaining: 64 }) => {
      if (!node || --budget.remaining < 0) return undefined;
      node = transparentExpression(node, budget);
      if (!node) return undefined;
      if (node.type === 'Literal') return typeof node.value === 'string' && node.value.length > 256 ? undefined : node.value;
      if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
        const value = node.quasis[0].value.cooked;
        return typeof value === 'string' && value.length <= 256 ? value : undefined;
      }
      if (node.type === 'Identifier') {
        const reference = context.sourceCode.getScope(node).references.find(item => item.identifier === node);
        const definitions = reference?.resolved?.defs;
        const definition = definitions?.length === 1 ? definitions[0] : undefined;
        if (definition?.type === 'Variable' && definition.parent?.kind === 'const'
          && definition.node.id.type === 'Identifier') return constantKey(definition.node.init, budget);
        return undefined;
      }
      if (node.type === 'ArrayExpression') {
        const values = node.elements.map(item => constantKey(item, budget));
        return values.every(value => typeof value === 'string') ? values : undefined;
      }
      if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression'
        && !node.callee.computed && node.callee.property.name === 'join'
        && node.arguments.length <= 1) {
        const separator = node.arguments.length ? constantKey(node.arguments[0], budget) : ',';
        const values = constantKey(node.callee.object, budget);
        if (typeof separator !== 'string' || !Array.isArray(values)) return undefined;
        const joined = values.join(separator);
        return joined.length <= 256 ? joined : undefined;
      }
      if (node?.type !== 'BinaryExpression' || node.operator !== '+') return undefined;
      const left = constantKey(node.left, budget);
      const right = constantKey(node.right, budget);
      return typeof left === 'string' && typeof right === 'string' && left.length + right.length <= 256 ? left + right : undefined;
    };
    const propertyName = node => {
      if (!node.computed) return node.property.name;
      return constantKey(node.property);
    };
    // Any function-valued initializer or assignment protects a mutable binding
    // and its aliases conservatively; bound the shared traversal budget.
    const knownFunction = (node, budget = { remaining: 64 }) => {
      if (!node) return false;
      if (--budget.remaining < 0) return true;
      node = transparentExpression(node, budget);
      if (!node) return budget.remaining < 0;
      if (['ArrowFunctionExpression', 'FunctionExpression', 'FunctionDeclaration'].includes(node.type)) return true;
      if (node.type !== 'Identifier') return false;
      const scope = context.sourceCode.getScope(node);
      let variable = scope.references.find(item => item.identifier === node)?.resolved;
      for (let current = scope; !variable && current; current = current.upper) variable = current.set.get(node.name);
      const definition = variable?.defs.length === 1 ? variable.defs[0] : undefined;
      if (definition?.type === 'FunctionName') return true;
      if (definition?.type === 'Variable') {
        if (knownFunction(definition.node.init, budget)) return true;
        for (const reference of variable.references) {
          if (--budget.remaining < 0) return true;
          if (reference.isWrite() && knownFunction(reference.writeExpr, budget)) return true;
        }
      }
      return false;
    };
    const capabilityAlias = (node, budget = { remaining: 16 }) => {
      if (!node) return false;
      if (--budget.remaining < 0) return true;
      node = transparentExpression(node, budget);
      if (!node) return budget.remaining < 0;
      if (node.type !== 'Identifier') return false;
      const scope = context.sourceCode.getScope(node);
      let variable = scope.references.find(item => item.identifier === node)?.resolved;
      for (let current = scope; !variable && current; current = current.upper) variable = current.set.get(node.name);
      const definition = variable?.defs.length === 1 ? variable.defs[0] : undefined;
      if (definition?.type === 'Variable') return capabilityAlias(definition.node.init, budget);
      const name = definition?.type === 'ImportBinding' ? definition.parent.source.value : undefined;
      return typeof name === 'string' && name.startsWith('.') &&
        /\/secret-capability(?:\.[cm]?[jt]s)?$/.test(resolve(dirname(context.filename), name).replaceAll('\\', '/'));
    };
    const source = node => {
      const name = node.source?.value;
      if (typeof name !== 'string') return;
      if (name.startsWith('.')) {
        const target = resolve(dirname(context.filename), name).replaceAll('\\', '/');
        if (/\/secret-capability(?:\.[cm]?[jt]s)?$/.test(target)) {
          const facadeExport = publicFacade && node.type === 'ExportNamedDeclaration'
            && node.specifiers.length && node.specifiers.every(item => item.local?.name === 'Secret' && item.exported?.name === 'Secret');
          if (!facadeExport && (!credential || node.type !== 'ImportDeclaration' || publicFacade)) report(node);
        }
        if (/\/commands\/bake\/write-out(?:\.[cm]?[jt]s)?$/i.test(target)
          && (!writerCaller || node.type !== 'ImportDeclaration')) report(node);
        return;
      }
      if (node.importKind === 'type') return;
      const builtin = name.replace(/^node:/, '');
      if (builtins.has(builtin) || network && (builtin === 'https' || builtin === 'http2') || (acl || ownershipQuery || gitHistory) && builtin === 'child_process') return;
      report(node);
    };
    return {
      ImportDeclaration: source,
      ExportNamedDeclaration(node) {
        source(node);
        if (!node.source && node.specifiers.some(item => capabilityAlias(item.local))) report(node);
        if (node.declaration?.type === 'VariableDeclaration'
          && node.declaration.declarations.some(item => capabilityAlias(item.init))) report(node);
      },
      ExportDefaultDeclaration(node) { if (capabilityAlias(node.declaration)) report(node); },
      ExportAllDeclaration: source,
      ImportExpression: report,
      CallExpression(node) {
        const callee = node.callee;
        if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier'
          && callee.object.name === 'Object' && propertyName(callee) === 'getOwnPropertyDescriptor'
          && ['constructor', '__proto__'].includes(constantKey(node.arguments[1]))) report(node);
      },
      Identifier(node) {
        if (['process', 'globalThis', 'global', 'navigator'].includes(node.name)) {
          const reference = context.sourceCode.getScope(node).references.find(item => item.identifier === node);
          if (reference?.isRead() && !reference.resolved?.defs.length
            && (node.parent.type !== 'MemberExpression' || node.parent.object !== node)) report(node);
        }
        if (!forbiddenGlobals.has(node.name)) return;
        const reference = context.sourceCode.getScope(node).references.find(item => item.identifier === node);
        if (reference?.isRead() && !reference.resolved?.defs.length) report(node);
      },
      MemberExpression(node) {
        const property = propertyName(node);
        if (['constructor', '__proto__'].includes(property)) report(node);
        // Unknown computed access on a function can recover its dynamic-code
        // constructor. Data objects keep ordinary computed property access.
        if (node.computed && property === undefined && knownFunction(node.object)) report(node);
        if (node.object.type !== 'Identifier') return;
        const key = node.computed ? node.property.value : node.property.name;
        if (['globalThis', 'global'].includes(node.object.name)
          && (node.computed || forbiddenGlobals.has(key) || key === 'process')) report(node);
        if (node.object.name === 'process' && (node.computed
          || ['getBuiltinModule', 'binding', '_linkedBinding', 'dlopen', 'mainModule'].includes(key))) report(node);
        if (node.object.name === 'navigator' && (node.computed || key === 'sendBeacon')) report(node);
      },
    };
  },
};

export default [
  { ignores: ['dist/**', 'node_modules/**', '.ratchet/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { languageOptions: { globals: { ...globals.node } } },
  {
    files: ['src/**/*.ts'],
    plugins: { macwarden: { rules: { 'capability-boundary': capabilityBoundary } } },
    rules: { 'macwarden/capability-boundary': 'error', 'no-eval': 'error', 'no-new-func': 'error' },
  },
];
