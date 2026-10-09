// Child processes receive only explicit operational inputs, never the host's
// registry, node endpoint, diagnostics, npm configuration, or credential flags.
export function childEnvironment(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const permitted = ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT',
    'USERNAME', 'USERDOMAIN', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME',
    'TMP', 'TEMP', 'TMPDIR', 'NPM_CONFIG_CACHE', 'NPM_CONFIG_USERCONFIG',
    'MACWARDEN_TEST_TMP', 'MACWARDEN_SENTINEL_DIR', 'MACWARDEN_FIXTURE_DIR', 'MACWARDEN_CP038_FIXTURE_TURN',
    'MACWARDEN_FIXTURE_SHARD'];
  // Docker discovers system-installed Windows CLI plugins under ProgramFiles.
  // Keep user configuration private while preserving this installation path.
  if (process.platform === 'win32') permitted.push('ProgramFiles');
  const env: NodeJS.ProcessEnv = {};
  for (const key of permitted) if (process.env[key] !== undefined) env[key] = process.env[key];
  return { ...env, NODE_OPTIONS: '', NODE_DEBUG: '', ...extra };
}
