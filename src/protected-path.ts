import type * as nodeFs from 'node:fs/promises';
import { basename, dirname, join, resolve, win32 } from 'node:path';

// SAFE-02 names are refused as complete path components before opening them.
export function isProtectedPath(path: string): boolean {
  return path.split(/[\\/]/).some(component => {
    // Windows alternate data streams use name:stream; protect the base file.
    const name = component.split(':', 1)[0].toLowerCase();
    return name === 'macaroons.db' || name === 'wallet.db' || name.endsWith('.key') ||
      /(^|[._-])(password|passwd|seed)([._-]|$)/.test(name) ||
      /^(?:wallet[-_.]?password(?:\..+)?|seeds?(?:\..+)?|tls[-_.]?(?:key|privkey)(?:\..+)?)$/.test(name);
  });
}

// Names Win32 path normalisation changes or maps to a device. Node opens the literal
// \\?\ object while Win32 tools (and other programs) open the normalised name, so a
// credential file must never carry one. COM/LPT also match the superscript digits.
const WINDOWS_DEVICE = /^(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]|conin\$|conout\$)(?:[ .]|$)/i;
// eslint-disable-next-line no-control-regex
const WINDOWS_INVALID = /[<>:"|?*\u0000-\u001f]/;

/**
 * Why an output path cannot be written as given on Windows, or null. Every component
 * after the drive or UNC share is checked: a trailing dot or space, a reserved device
 * name (with or without an extension, any case), ':' (an alternate data stream) or a
 * character Windows forbids. Device namespace paths (\\.\) are refused. Other
 * platforms accept these names, so the check applies only on Windows.
 */
export function outputNameProblem(path: string, platform: NodeJS.Platform = process.platform): string | null {
  if (platform !== 'win32') return null;
  const absolute = win32.resolve(path);
  if (/^[\\/]{2}\.[\\/]/.test(absolute)) return 'a Windows device namespace path (\\\\.\\) is refused';
  const root = win32.parse(absolute).root;
  for (const component of absolute.slice(root.length).split('\\')) {
    if (!component) continue;
    if (WINDOWS_INVALID.test(component))
      return 'a path component contains ":" (an alternate data stream) or a character Windows does not allow in names';
    if (/[. ]$/.test(component)) return 'a path component ends with a dot or a space, which Windows removes';
    if (WINDOWS_DEVICE.test(component)) return 'a path component is a reserved Windows device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9)';
  }
  return null;
}

export async function resolveUnprotectedPath(path: string,
  fs: Pick<typeof nodeFs, 'realpath' | 'lstat'>): Promise<string> {
  if (isProtectedPath(path)) throw new Error('protected path');
  let candidate = resolve(path);
  const missing: string[] = [];
  for (;;) {
    if (isProtectedPath(candidate)) throw new Error('protected path');
    let resolved: string;
    try { resolved = await fs.realpath(candidate); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      // A dangling symlink must not become a creation path to an unchecked target.
      try { await fs.lstat(candidate); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const parent = dirname(candidate);
        if (parent === candidate) throw error;
        missing.unshift(basename(candidate));
        candidate = parent;
        continue;
      }
      throw new Error('unresolvable path', { cause: error });
    }
    const selected = join(resolved, ...missing);
    if (isProtectedPath(selected)) throw new Error('protected path');
    return selected;
  }
}
