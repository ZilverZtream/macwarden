import { execFile } from 'node:child_process';
import { lstat, mkdtemp, realpath, rm } from 'node:fs/promises';
import { join, resolve, win32 } from 'node:path';
import { promisify } from 'node:util';

const execute = promisify(execFile);

function windowsTool(name) {
  const root = process.env.SystemRoot ?? 'C:\\Windows';
  if (!win32.isAbsolute(root)) throw new Error('invalid Windows system directory');
  return win32.join(root, 'System32', name);
}

function canonicalSid(identity) {
  if (typeof identity !== 'string' || !/^S-1-(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*)){1,15}$/.test(identity)) return false;
  const [authority, ...subAuthorities] = identity.slice(4).split('-').map(value => BigInt(value));
  return authority <= 0xffffffffffffn && subAuthorities.every(value => value <= 0xffffffffn);
}

async function windowsIdentityAndAcl(directory, restrict = false) {
  // Decode path data rather than inserting user content into executable script.
  // New directories are restricted and freshly inspected in the same process;
  // borrowed directories are inspected on every call without changing the ACL.
  const encodedPath = Buffer.from(directory, 'utf16le').toString('base64');
  const script = [
    "$ErrorActionPreference='Stop'; try {",
    `$directory=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${encodedPath}'));`,
    '$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;',
    ...(restrict ? [
      '$acl=[System.Security.AccessControl.DirectorySecurity]::new();',
      '$acl.SetOwner($user); $acl.SetAccessRuleProtection($true,$false);',
      '$rule=[System.Security.AccessControl.FileSystemAccessRule]::new($user,[System.Security.AccessControl.FileSystemRights]::FullControl,[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Allow);',
      '$acl.AddAccessRule($rule); [System.IO.Directory]::SetAccessControl($directory,$acl);',
    ] : []),
    '$acl=Get-Acl -LiteralPath $directory;',
    '[pscustomobject]@{identity=$user.Value; owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object { [pscustomobject]@{sid=$_.IdentityReference.Value; type=$_.AccessControlType.ToString()} })} | ConvertTo-Json -Compress -Depth 4;',
    '} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }',
  ].join('\n');
  const { stdout } = await execute(windowsTool('WindowsPowerShell\\v1.0\\powershell.exe'),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { shell: false, windowsHide: true, timeout: 60_000, maxBuffer: 16_384 });
  const acl = JSON.parse(stdout);
  if (!canonicalSid(acl.identity) || acl.owner !== acl.identity || !Array.isArray(acl.rules) ||
      !acl.rules.some(rule => rule.type === 'Allow' && rule.sid === acl.identity) ||
      acl.rules.some(rule => !canonicalSid(rule.sid) || (rule.type === 'Allow' && rule.sid !== acl.identity))) {
    throw new Error('scratch root must have an owner-only Windows ACL');
  }
}

async function realDirectory(directory) {
  const path = resolve(directory);
  const info = await lstat(path);
  const canonical = await realpath(path);
  if (!info.isDirectory() || info.isSymbolicLink() ||
      (process.platform === 'win32' ? canonical.toLowerCase() !== path.toLowerCase() : canonical !== path)) {
    throw new Error('scratch root must be a real directory');
  }
  return info;
}

/** Refuse unsafe caller-owned roots without modifying their permissions.
 * @param {string} directory
 * @returns {Promise<void>}
 */
export async function assertPrivateDirectory(directory) {
  const path = resolve(directory);
  const info = await realDirectory(path);
  if (process.platform === 'win32') {
    await windowsIdentityAndAcl(path);
  } else if (info.uid !== process.getuid() || (info.mode & 0o077) !== 0) {
    throw new Error('scratch root must be owned and private');
  }
}

/** Inspect every supplied directory freshly within this operation.
 * @param {string[]} directories
 * @returns {Promise<void>}
 */
export async function assertPrivateDirectories(directories) {
  if (!Array.isArray(directories) || directories.length === 0 ||
      directories.some(directory => typeof directory !== 'string' || !directory)) {
    throw new Error('scratch directories are required');
  }
  const paths = directories.map(directory => resolve(directory));
  const before = [];
  for (const path of paths) {
    const info = await realDirectory(path);
    if (process.platform !== 'win32' && (info.uid !== process.getuid() || (info.mode & 0o077) !== 0)) {
      throw new Error('scratch root must be owned and private');
    }
    before.push(info);
  }
  if (process.platform === 'win32') {
    const encodedPaths = Buffer.from(JSON.stringify(paths), 'utf16le').toString('base64');
    const script = [
      "$ErrorActionPreference='Stop'; try {",
      `$paths=ConvertFrom-Json -InputObject ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${encodedPaths}')));`,
      '$results=@(for ($index=0; $index -lt $paths.Count; $index++) {',
      '$directory=$paths[$index]; $user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;',
      '$acl=Get-Acl -LiteralPath $directory;',
      '[pscustomobject]@{index=$index; directory=$directory; identity=$user.Value; owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object { [pscustomobject]@{sid=$_.IdentityReference.Value; type=$_.AccessControlType.ToString()} })}',
      '}); [pscustomobject]@{results=$results} | ConvertTo-Json -Compress -Depth 5;',
      '} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }',
    ].join('\n');
    const { stdout } = await execute(windowsTool('WindowsPowerShell\\v1.0\\powershell.exe'),
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { shell: false, windowsHide: true, timeout: 60_000, maxBuffer: 16_384 });
    const report = JSON.parse(stdout);
    if (!report || typeof report !== 'object' || Object.keys(report).length !== 1 ||
        !Array.isArray(report.results) || report.results.length !== paths.length) {
      throw new Error('invalid scratch directory inspection');
    }
    for (let index = 0; index < paths.length; index++) {
      const acl = report.results[index];
      if (!acl || typeof acl !== 'object' || Object.keys(acl).length !== 5 ||
          acl.index !== index || acl.directory !== paths[index] ||
          !canonicalSid(acl.identity) || acl.owner !== acl.identity || !Array.isArray(acl.rules) ||
          acl.rules.some(rule => !rule || typeof rule !== 'object' || Object.keys(rule).length !== 2 ||
            !canonicalSid(rule.sid) || !['Allow', 'Deny'].includes(rule.type) ||
            (rule.type === 'Allow' && rule.sid !== acl.identity)) ||
          !acl.rules.some(rule => rule.type === 'Allow' && rule.sid === acl.identity)) {
        throw new Error('scratch root must have an owner-only Windows ACL');
      }
    }
  }
  for (let index = 0; index < paths.length; index++) {
    const info = await realDirectory(paths[index]);
    if (info.dev !== before[index].dev || info.ino !== before[index].ino ||
        (process.platform !== 'win32' && (info.uid !== process.getuid() || (info.mode & 0o077) !== 0))) {
      throw new Error('scratch directory changed during inspection');
    }
  }
}

/** Create an empty owned root and restrict it before any caller can copy secrets.
 * @param {string} parent
 * @param {string} prefix
 * @returns {Promise<string>}
 */
export async function createPrivateDirectory(parent, prefix) {
  if (typeof prefix !== 'string' || !prefix || /[\\/]/.test(prefix)) {
    throw new Error('invalid scratch prefix');
  }
  const directory = await mkdtemp(join(resolve(parent), prefix));
  try {
    if (process.platform === 'win32') {
      await realDirectory(directory);
      await windowsIdentityAndAcl(directory, true);
      await realDirectory(directory);
    } else await assertPrivateDirectory(directory);
    return directory;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    // The reason names the failing step (timeout, ACL check), never secret material.
    const reason = !(error instanceof Error) ? 'unknown'
      : /** @type {{ killed?: boolean }} */ (error).killed ? 'powershell timed out'
      : String(/** @type {{ stderr?: unknown }} */ (error).stderr || '').trim().slice(0, 300) || error.message.slice(0, 120);
    throw new Error(`private scratch directory creation failed: ${reason}`, { cause: error });
  }
}
