// Owner-only file creation, shared by every file macwarden writes for itself: credential
// outputs (the bake writer), the registry and its sidecars (usage file, canary configuration)
// and the payment journal (audit 1.2.1: those relied on mode 0600, which Windows does not
// implement, so in a folder with permissive inherited permissions another account could read
// or change them).
//
// POSIX: create 0600 with O_EXCL, then prove the mode through the open descriptor. File
// systems that cannot store modes (WSL drvfs, vfat, exFAT, CIFS) report other bits; chmod
// is tried once and, if the file is still not private, it is removed and nothing is written.
//
// Windows: a fixed System32 PowerShell helper creates the file with an owner-only, protected
// DACL in the same call that creates it, so no other principal is ever granted access and
// none can hold a handle to it (not even one that only changes permissions). The file is
// then opened with share mode 0, and the owner and DACL of the object at the path are read
// back while that handle is held: the owner must be this user and the DACL must grant only
// this user. The same helper reads an existing file's owner and DACL back (verifyOwnerOnly).
import * as nodeFs from 'node:fs/promises';
import { constants } from 'node:fs';
import { win32 } from 'node:path';
import { execFile } from 'node:child_process';

export type PrivateFs = Pick<typeof nodeFs, 'open' | 'unlink'>;
export type OwnerOnlyFile = { handle: nodeFs.FileHandle; aclWarning: boolean };

/** Creation failed: `share` when another process holds or replaced the file, `reserve` otherwise. */
export class PrivateFileError extends Error {
  readonly kind: 'reserve' | 'share';
  readonly code?: string;
  constructor(message: string, kind: 'reserve' | 'share' = 'reserve', code?: string) {
    super(message);
    this.name = 'PrivateFileError';
    this.kind = kind;
    this.code = code;
  }
}

// libuv's UV_FS_O_EXLOCK: on Windows the file is opened with share mode 0, so the
// open fails while any other handle with data access exists, and no such handle can
// be opened while it is held. Node does not export the constant; libuv passes it through.
const UV_FS_O_EXLOCK = 0x10000000;

/**
 * Creates `path` (which must not exist) owner-only before any byte is written, and verifies
 * that; anything else fails before writing (PrivateFileError). `aclWarning` is true only on a
 * Windows volume that stores no permissions (FAT, exFAT). An existing path fails with
 * `code: 'EEXIST'` on every platform.
 */
export async function reserveOwnerOnly(path: string, fs: PrivateFs = nodeFs): Promise<OwnerOnlyFile> {
  return process.platform === 'win32' ? reserveWindows(path, fs) : reservePosix(path, fs);
}

/**
 * Windows only: whether the existing file at `path` is owned by this user with a protected
 * DACL granting only this user (`ownerOnly`), or lies on a volume that stores no permissions
 * (`noAcl`). Null when that could not be read. On other platforms the caller checks the mode
 * through its own descriptor.
 */
export async function verifyOwnerOnly(path: string): Promise<{ ownerOnly: boolean; noAcl: boolean } | null> {
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  if (!win32.isAbsolute(systemRoot)) return null;
  const found = await runHelper(path, systemRoot, 'verify');
  if (!found || typeof found.sid !== 'string' || !SID.test(found.sid)) return null;
  if (found.noAcl === true) return { ownerOnly: false, noAcl: true };
  return { ownerOnly: privateEnough(parseAcl(found.acl), found.sid), noAcl: false };
}

async function reservePosix(path: string, fs: PrivateFs): Promise<OwnerOnlyFile> {
  let handle: nodeFs.FileHandle;
  try { handle = await fs.open(path, 'wx', 0o600); }
  catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new PrivateFileError(code === 'EEXIST' ? 'the file already exists' : 'cannot create the file', 'reserve', code);
  }
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
  throw new PrivateFileError('the file system did not keep owner-only mode 0600; nothing was written');
}

async function reserveWindows(path: string, fs: PrivateFs): Promise<OwnerOnlyFile> {
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  if (!win32.isAbsolute(systemRoot)) throw new PrivateFileError('invalid Windows system directory');
  const creation = await createPrivateFile(path, systemRoot);
  if (creation === 'exists') throw new PrivateFileError('the file already exists', 'reserve', 'EEXIST');
  if (!creation) throw new PrivateFileError('could not create the file with owner-only permissions');
  let handle: nodeFs.FileHandle;
  try { handle = await fs.open(path, constants.O_RDWR | UV_FS_O_EXLOCK); }
  catch {
    // Another handle exists (EBUSY) or the file is gone. Nothing has been written.
    creation.end();
    await fs.unlink(path).catch(() => undefined);
    throw new PrivateFileError('the file was opened or replaced by another process before it was written', 'share');
  }
  // FAT and exFAT keep no owner and no ACL, so there is nothing to verify.
  if (creation.noAcl) { creation.end(); return { handle, aclWarning: true }; }
  const found = await creation.verify();
  if (!found || found.owner !== creation.sid) {
    // Not provably the file the helper created: do not write to it or delete it.
    await handle.close();
    throw new PrivateFileError('the file was opened or replaced by another process before it was written', 'share');
  }
  if (!ownerOnly(found, creation.sid)) {
    try { await handle.close(); } finally { await fs.unlink(path).catch(() => undefined); }
    throw new PrivateFileError('the file did not keep owner-only permissions (another account has access); nothing was written');
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
// In verify mode it only reads the owner and DACL of the existing file back. The path and
// the mode arrive through the environment, never through the command text.
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
$path = $env:MACWARDEN_PRIVATE_OUT
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User
# FAT and exFAT volumes store no Windows permissions at all.
$noAcl = $false
try { $noAcl = (New-Object IO.DriveInfo([IO.Path]::GetPathRoot($path))).DriveFormat -match '^(FAT|FAT12|FAT16|FAT32|exFAT)$' } catch { $noAcl = $false }
if ($env:MACWARDEN_PRIVATE_MODE -eq 'verify') {
  $found = $null
  if (-not $noAcl) { try { $found = Describe ([IO.File]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]'Owner, Access')) } catch { $found = $null } }
  [Console]::Out.WriteLine('VERIFIED ' + (@{ sid = $me.Value; noAcl = $noAcl; acl = $found } | ConvertTo-Json -Compress -Depth 4)); [Console]::Out.Flush()
  exit 0
}
try {
  if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) { [Console]::Out.WriteLine('EXISTS'); exit 1 }
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
} catch [System.IO.IOException] {
  if ([IO.File]::Exists($path)) { [Console]::Out.WriteLine('EXISTS') } else { [Console]::Out.WriteLine('FAILED') }
  exit 1
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

// Principals that can read any file on the machine regardless of its DACL, as root can on POSIX:
// an existing file granting them is still owner-only in the sense mode 0600 is.
const SYSTEM = 'S-1-5-18';
const ADMINISTRATORS = 'S-1-5-32-544';

/**
 * True when an existing file is owned by `sid` and every allowing entry, inherited or not, is for
 * `sid`, SYSTEM or the Administrators group: nothing a file created 0600 would not grant.
 * Looser than ownerOnly (which proves what the helper itself created) because a file in an
 * owner-only folder inherits that folder's entries rather than carrying protected ones.
 */
function privateEnough(acl: WindowsAcl | null, sid: string): boolean {
  return !!acl && acl.owner === sid && acl.rules.some(rule => rule.allow)
    && acl.rules.every(rule => !rule.allow || rule.sid === sid || rule.sid === SYSTEM || rule.sid === ADMINISTRATORS);
}

/** True when the ACL grants only `sid`, nothing is inherited, and `sid` owns the object. */
function ownerOnly(acl: WindowsAcl | null, sid: string): boolean {
  return !!acl && acl.owner === sid && acl.protected && acl.rules.length > 0
    && acl.rules.every(rule => rule.sid === sid && rule.allow && !rule.inherited);
}

type HelperChild = {
  /** Resolves with the rest of the first output line starting with `prefix`, or null once the helper exited without one. */
  next(prefix: string): Promise<string | null>;
  write(line: string): void;
  end(): void;
};

/** Starts the fixed System32 PowerShell helper for `path`; null when it cannot be started. */
function startHelper(path: string, systemRoot: string, mode: 'create' | 'verify'): HelperChild | null {
  const executable = win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
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
  let child: ReturnType<typeof execFile> | undefined;
  try {
    child = execFile(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from(helperScript, 'utf16le').toString('base64')], {
      shell: false, windowsHide: true, timeout: 20_000, maxBuffer: 64 * 1024, encoding: 'utf8',
      env: { SystemRoot: systemRoot, WINDIR: systemRoot, PATH: win32.join(systemRoot, 'System32'),
        PSModulePath: win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules'),
        MACWARDEN_PRIVATE_OUT: path, MACWARDEN_PRIVATE_MODE: mode },
    }, (_error, stdout) => {
      // The callback carries the complete output; streamed chunks may not all have arrived.
      if (typeof stdout === 'string' && stdout.length > buffered.length) buffered = stdout;
      buffered += '\n'; exited = true; deliver();
    }) as ReturnType<typeof execFile> | undefined;
  } catch { child = undefined; }
  if (!child?.stdout || !child.stdin) return null;
  const stdin = child.stdin;
  stdin.on('error', () => undefined);
  child.stdout.on('data', (chunk: string | Buffer) => { if (!exited) { buffered += String(chunk); deliver(); } });
  return {
    next: prefix => new Promise<string | null>(settle => { waiting.push({ prefix, settle }); deliver(); }),
    write: line => { try { stdin.write(`${line}\n`); } catch { /* the helper already exited */ } },
    end: () => { try { stdin.end(); } catch { /* the helper already exited */ } },
  };
}

/** The helper's one reply in verify mode, parsed; null when it gave none. */
async function runHelper(path: string, systemRoot: string, mode: 'verify'): Promise<Record<string, unknown> | null> {
  const helper = startHelper(path, systemRoot, mode);
  if (!helper) return null;
  const line = await helper.next('VERIFIED ');
  helper.end();
  try { return line === null ? null : JSON.parse(line) as Record<string, unknown>; } catch { return null; }
}

/**
 * Creates `path` (which must not exist) with an owner-only security descriptor through the
 * fixed System32 PowerShell helper, then keeps the helper waiting so the caller can verify
 * the object at the path after opening it exclusively. 'exists' when the path already
 * existed; null when the helper did not report a created file (unavailable or failed).
 */
async function createPrivateFile(path: string, systemRoot: string): Promise<PrivateCreation | 'exists' | null> {
  const helper = startHelper(path, systemRoot, 'create');
  if (!helper) return null;
  const outcome = await Promise.race([
    helper.next('CREATED ').then(line => ({ kind: 'created' as const, line })),
    helper.next('EXISTS').then(() => ({ kind: 'exists' as const, line: null })),
  ]);
  if (outcome.kind === 'exists') { helper.end(); return 'exists'; }
  let reply: Record<string, unknown> | null;
  try { reply = outcome.line === null ? null : JSON.parse(outcome.line) as Record<string, unknown>; } catch { reply = null; }
  if (!reply || typeof reply.sid !== 'string' || !SID.test(reply.sid)) { helper.end(); return null; }
  let verified: Promise<WindowsAcl | null> | undefined;
  return { sid: reply.sid, noAcl: reply.noAcl === true, created: parseAcl(reply.acl), end: helper.end,
    verify: () => verified ??= (async () => {
      helper.write('verify');
      const found = await helper.next('VERIFIED ');
      helper.end();
      try { return found === null ? null : parseAcl((JSON.parse(found) as { acl?: unknown }).acl); }
      catch { return null; }
    })() };
}
