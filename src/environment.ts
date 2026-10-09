export function unsafeNodeDiagnostics(env: Record<string, string | undefined>): boolean {
  const debug = (env.NODE_DEBUG ?? '').split(/[\s,]+/).some(pattern => {
    // Node's debug categories support '*' wildcards; other metacharacters are literal.
    const expression = pattern.replace(/[|\\{}()[\]^$+?.]/g, '\\$&').replace(/\*/g, '.*');
    const enabled = new RegExp(`^${expression}$`, 'i');
    return ['http', 'https', 'tls', 'net'].some(category => enabled.test(category));
  });
  return debug || (env.NODE_OPTIONS ?? '').length > 0;
}
