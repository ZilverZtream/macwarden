import { revealSecret } from '../../secret-capability.js';
import * as nodeFs from 'node:fs/promises';
import { constants } from 'node:fs';
import { win32 } from 'node:path';
import type { Secret } from '../../secret.js';
import { outputNameProblem } from '../../protected-path.js';
import { execFile } from 'node:child_process';
import { OutputReserveError } from './out-errors.js';

export type ReservedOut = { write(mac: Secret): Promise<void>; discard(): Promise<void> };

// libuv's UV_FS_O_EXLOCK: on Windows the file is opened with share mode 0, so the
// open fails while any other handle with data access exists, and no such handle can
// be opened while it is held. Node does not export the constant; libuv passes it through.
const UV_FS_O_EXLOCK = 0x10000000;

class OutputShareError extends OutputReserveError {
  constructor() { super('output file was opened or replaced by another process before it was written'); this.name = 'OutputShareError'; }
}

/**
 * Creates `path` exclusively for one credential (or report) and returns a reservation that
 * writes it through a handle no other process holds. The file is owner-only before any byte
 * is written, and that is verified; anything else fails before writing. `aclWarning` is true
 * only on a Windows volume that stores no permissions (FAT, exFAT).
 */
export async function reserveOut(path: string, fs: typeof nodeFs = nodeFs): Promise<{
  reservation: ReservedOut;
  aclWarning: boolean;
}> {
  const nameProblem = outputNameProblem(path);
  if (nameProblem) throw new OutputReserveError(nameProblem);
  const reserved = process.platform === 'win32' ? await reserveWindows(path, fs) : await reservePosix(path, fs);
  const handle = reserved.handle;
  let written = false;
  return {
    aclWarning: reserved.aclWarning,
    reservation: {
      async write(mac) {
        await handle.writeFile(revealSecret(mac));
        await handle.sync();
        await handle.close();
        written = true;
      },
      async discard() {
        if (written) return;
        // The exclusive handle refuses deletion, so close before unlinking.
        try { await handle.close(); } finally { await fs.unlink(path); }
      },
    },
  };
}

// POSIX: create 0600 with O_EXCL, then prove the mode through the open descriptor. File
// systems that cannot store modes (WSL drvfs, vfat, exFAT, CIFS) report other bits; chmod
// is tried once and, if the file is still not private, it is removed and nothing is written.
async function reservePosix(path: string, fs: typeof nodeFs): Promise<{ handle: nodeFs.FileHandle; aclWarning: boolean }> {
  const handle = await fs.open(path, 'wx', 0o600);
  const uid = process.getuid?.();
  const private_ = async () => {
    const stat = await handle.stat();
    return (stat.mode & 0o077) === 0 && (uid === undefined || stat.uid === uid);
  };
  try {
    if (await private_()) return { handle, aclWarning: false };
    await handle.chmod(0o600).catch(() => undefined);
    if (await private_()) return { handle, aclWarning: false };
  } catch { /* checked below as not private */ }
  try { await handle.close(); } finally { await fs.unlink(path).catch(() => undefined); }
  throw new OutputReserveError('the file system did not keep owner-only mode 0600; nothing was written');
}

// Windows: the fixed helper creates the file with an owner-only, protected DACL in the same
// call that creates it, so no other principal is ever granted access and none can hold a
// handle to it (not even one that only changes permissions). The file is then opened with
// share mode 0, and the owner and DACL of the object at the path are read back while that
// handle is held: the owner must be this user and the DACL must grant only this user.
async function reserveWindows(path: string, fs: typeof nodeFs): Promise<{ handle: nodeFs.FileHandle; aclWarning: boolean }> {
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  if (!win32.isAbsolute(systemRoot)) throw new OutputReserveError('invalid Windows system directory');
  const creation = await createPrivateFile(path, systemRoot);
  if (!creation) throw new OutputReserveError('could not create the file with owner-only permissions');
  let handle: nodeFs.FileHandle;
  try { handle = await fs.open(path, constants.O_RDWR | UV_FS_O_EXLOCK); }
  catch {
    // Another handle exists (EBUSY) or the file is gone. Nothing has been written.
    creation.end();
    await fs.unlink(path).catch(() => undefined);
    throw new OutputShareError();
  }
  // FAT and exFAT keep no owner and no ACL, so there is nothing to verify.
  if (creation.noAcl) { creation.end(); return { handle, aclWarning: true }; }
  const found = await creation.verify();
  if (!found || found.owner !== creation.sid) {
    // Not provably the file the helper created: do not write to it or delete it.
    await handle.close();
    throw new OutputShareError();
  }
  if (!ownerOnly(found, creation.sid)) {
    try { await handle.close(); } finally { await fs.unlink(path).catch(() => undefined); }
    throw new OutputReserveError('the file did not keep owner-only permissions (another account has access); nothing was written');
  }
  return { handle, aclWarning: false };
}

// --- Windows owner-only creation helper -------------------------------------------

/** A file's owner and DACL as read back from Windows, by SID; null when the volume keeps none. */
type WindowsAcl = {
  owner: string | null;
  protected: boolean;
  rules: { sid: string; allow: boolean; inherited: boolean; rights: number }[];
};

type PrivateCreation = {
  /** The SID of the account that created the file (this process's user). */
  sid: string;
  /** True when the volume stores no Windows permissions (FAT, exFAT): the file was created without an ACL. */
  noAcl: boolean;
  /** The security descriptor read back through the creating handle; null when it could not be read. */
  created: WindowsAcl | null;
  /** Reads the owner and DACL of the object now at the path (call while holding the exclusive handle). */
  verify(): Promise<WindowsAcl | null>;
  /** Ends the helper without a further check. */
  end(): void;
};

const SID = /^S-1-\d+(?:-\d+)+$/;

// The fixed helper creates the file with CreateNew and a security descriptor that is
// private from the first instant: owner = this user, a protected DACL (nothing inherited)
// and one ACE granting this user full control. No other principal is ever granted access,
// so none can open a handle to the file, including one that only changes its permissions.
// The path arrives through the environment, never through the command text.
const helperScript = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Load the Microsoft.PowerShell.Utility cmdlets used below from the pinned module
# path by name. Autoloading them first analyses every module on the path, which took 18 to 33 s
# on GitHub's Windows runners in this environment (no PSModuleAnalysisCachePath).
Import-Module Microsoft.PowerShell.Utility
function Describe($sec) {
  $owner = $sec.GetOwner([Security.Principal.SecurityIdentifier])
  $rules = @($sec.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
    @{ sid = $_.IdentityReference.Value; allow = ($_.AccessControlType -eq 'Allow'); inherited = $_.IsInherited; rights = [int64]$_.FileSystemRights } })
  return @{ owner = $(if ($owner) { $owner.Value } else { $null }); protected = $sec.AreAccessRulesProtected; rules = $rules }
}
try {
  $path = $env:MACWARDEN_PRIVATE_OUT
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
  # FAT and exFAT volumes store no Windows permissions at all.
  $noAcl = $false
  try { $noAcl = (New-Object IO.DriveInfo([IO.Path]::GetPathRoot($path))).DriveFormat -match '^(FAT|FAT12|FAT16|FAT32|exFAT)$' } catch { $noAcl = $false }
  if ($noAcl) {
    $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $stream.Dispose(); $created = $null
  } else {
    $sec = New-Object Security.AccessControl.FileSecurity
    $sec.SetOwner($me)
    $sec.SetAccessRuleProtection($true, $false)
    $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)))
    $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $sec)
    try { $created = Describe $stream.GetAccessControl() } catch { $created = @{ unreadable = $true } } finally { $stream.Dispose() }
  }
} catch { [Console]::Out.WriteLine('FAILED'); exit 1 }
[Console]::Out.WriteLine('CREATED ' + (@{ sid = $me.Value; noAcl = $noAcl; acl = $created } | ConvertTo-Json -Compress -Depth 4)); [Console]::Out.Flush()
if ([Console]::In.ReadLine() -ne 'verify') { exit 0 }
try { $found = Describe ([IO.File]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]'Owner, Access')) } catch { $found = $null }
[Console]::Out.WriteLine('VERIFIED ' + (@{ acl = $found } | ConvertTo-Json -Compress -Depth 4)); [Console]::Out.Flush()
`;

function parseAcl(value: unknown): WindowsAcl | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  const rules = Array.isArray(record.rules) ? record.rules : record.rules && typeof record.rules === 'object' ? [record.rules] : null;
  if (!rules || typeof record.protected !== 'boolean') return null;
  const parsed: WindowsAcl['rules'] = [];
  for (const rule of rules as Record<string, unknown>[]) {
    if (!rule || typeof rule.sid !== 'string' || typeof rule.allow !== 'boolean'
      || typeof rule.inherited !== 'boolean' || typeof rule.rights !== 'number') return null;
    parsed.push({ sid: rule.sid, allow: rule.allow, inherited: rule.inherited, rights: rule.rights });
  }
  return { owner: typeof record.owner === 'string' ? record.owner : null, protected: record.protected, rules: parsed };
}

/** True when the ACL grants only `sid`, nothing is inherited, and `sid` owns the object. */
function ownerOnly(acl: WindowsAcl | null, sid: string): boolean {
  return !!acl && acl.owner === sid && acl.protected && acl.rules.length > 0
    && acl.rules.every(rule => rule.sid === sid && rule.allow && !rule.inherited);
}

/**
 * Creates `path` (which must not exist) with an owner-only security descriptor through the
 * fixed System32 PowerShell helper, then keeps the helper waiting so the caller can verify
 * the object at the path after opening it exclusively. Null when the helper did not report
 * a created file (the path already existed, or the helper is unavailable or failed).
 */
function createPrivateFile(path: string, systemRoot: string): Promise<PrivateCreation | null> {
  const executable = win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  return new Promise(resolve => {
    let buffered = '';
    let exited = false;
    const waiting: Array<{ prefix: string; settle: (line: string | null) => void }> = [];
    const complete = (prefix: string) => buffered.split(/\r?\n/).slice(0, -1).find(line => line.startsWith(prefix));
    const deliver = () => {
      for (const item of [...waiting]) {
        const line = complete(item.prefix);
        if (line !== undefined || exited) { waiting.splice(waiting.indexOf(item), 1); item.settle(line === undefined ? null : line.slice(item.prefix.length)); }
      }
    };
    const next = (prefix: string) => new Promise<string | null>(settle => { waiting.push({ prefix, settle }); deliver(); });
    let child: ReturnType<typeof execFile> | undefined;
    try {
      child = execFile(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
        Buffer.from(helperScript, 'utf16le').toString('base64')], {
        shell: false, windowsHide: true, timeout: 20_000, maxBuffer: 64 * 1024, encoding: 'utf8',
        env: { SystemRoot: systemRoot, WINDIR: systemRoot, PATH: win32.join(systemRoot, 'System32'),
          PSModulePath: win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules'),
          MACWARDEN_PRIVATE_OUT: path },
      }, (_error, stdout) => {
        // The callback carries the complete output; streamed chunks may not all have arrived.
        if (typeof stdout === 'string' && stdout.length > buffered.length) buffered = stdout;
        buffered += '\n'; exited = true; deliver();
      }) as ReturnType<typeof execFile> | undefined;
    } catch { child = undefined; }
    if (!child?.stdout || !child.stdin) { resolve(null); return; }
    const stdin = child.stdin;
    stdin.on('error', () => undefined);
    child.stdout.on('data', (chunk: string | Buffer) => { if (!exited) { buffered += String(chunk); deliver(); } });
    const end = () => { try { stdin.end(); } catch { /* the helper already exited */ } };
    void next('CREATED ').then(line => {
      let reply: Record<string, unknown> | null;
      try { reply = line === null ? null : JSON.parse(line) as Record<string, unknown>; } catch { reply = null; }
      if (!reply || typeof reply.sid !== 'string' || !SID.test(reply.sid)) { end(); resolve(null); return; }
      let verified: Promise<WindowsAcl | null> | undefined;
      resolve({ sid: reply.sid, noAcl: reply.noAcl === true, created: parseAcl(reply.acl), end,
        verify: () => verified ??= (async () => {
          try { stdin.write('verify\n'); } catch { return null; }
          const found = await next('VERIFIED ');
          end();
          try { return found === null ? null : parseAcl((JSON.parse(found) as { acl?: unknown }).acl); }
          catch { return null; }
        })() });
    });
  });
}
