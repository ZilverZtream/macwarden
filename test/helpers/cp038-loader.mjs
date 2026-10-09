import { registerHooks } from 'node:module';
// Execute public TypeScript APIs in a child without building or inspecting production files.
registerHooks({ resolve(specifier, context, nextResolve) {
  try { return nextResolve(specifier, context); }
  catch (error) {
    if (specifier.startsWith('.') && specifier.endsWith('.js') && error.code === 'ERR_MODULE_NOT_FOUND')
      return nextResolve(specifier.slice(0, -3) + '.ts', context);
    throw error;
  }
} });
