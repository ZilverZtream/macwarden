import * as fs from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { join, isAbsolute } from 'node:path';

export type ProcessDomain = { platform: 'linux'; bootId: string; pidNamespace: string }
  | { platform: 'win32'; bootId: string; siloId: string };
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function validDomain(value: unknown): value is ProcessDomain {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.platform === 'linux') return Object.keys(record).length === 3
    && typeof record.bootId === 'string' && guid.test(record.bootId)
    && typeof record.pidNamespace === 'string' && /^[0-9]+:[1-9][0-9]*$/.test(record.pidNamespace);
  return record.platform === 'win32' && Object.keys(record).length === 3
    && typeof record.bootId === 'string' && guid.test(record.bootId)
    && record.bootId !== '00000000-0000-0000-0000-000000000000'
    && typeof record.siloId === 'string' && /^(host|[1-9][0-9]*)$/.test(record.siloId);
}

// Fixed trusted helper inherits this invocation's effective process domain.
// Missing native exports and query failures remain unverifiable.
const windowsQuery = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Load the Microsoft.PowerShell.Utility cmdlets used below from the pinned module
# path by name. Autoloading them first analyses every module on the path, which took 18 to 33 s
# on GitHub's Windows runners in this environment (no PSModuleAnalysisCachePath).
Import-Module Microsoft.PowerShell.Utility
try {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class MacwardenProcessDomain {
  [StructLayout(LayoutKind.Sequential)] public struct BootEnvironment {
    public Guid BootIdentifier;
    public Int32 FirmwareType;
    public UInt64 BootFlags;
  }
  [DllImport("ntdll.dll", ExactSpelling=true)] static extern UInt32 RtlGetCurrentServiceSessionId();
  [DllImport("ntdll.dll", ExactSpelling=true)] static extern Int32 NtQuerySystemInformation(Int32 kind, out BootEnvironment info, UInt32 size, out UInt32 returned);
  public static string BootId() {
    BootEnvironment info; UInt32 returned;
    if (Marshal.SizeOf(typeof(BootEnvironment)) != 32
        || NtQuerySystemInformation(90, out info, 32, out returned) != 0
        || returned != 32 || info.BootIdentifier == Guid.Empty)
      throw new Exception("ownership query failed");
    return info.BootIdentifier.ToString("D");
  }
  public static string Query() {
    UInt32 session = RtlGetCurrentServiceSessionId();
    return session == 0 ? "host" : session.ToString(System.Globalization.CultureInfo.InvariantCulture);
  }
}
'@
$silo = [MacwardenProcessDomain]::Query()
$boot = [MacwardenProcessDomain]::BootId()
@{ platform='win32'; bootId=$boot; siloId=$silo } | ConvertTo-Json -Compress
} catch { exit 1 }
`;

function windowsDomain(): Promise<ProcessDomain | null> {
  const root = process.env.SystemRoot;
  if (!root || !isAbsolute(root)) return Promise.resolve(null);
  const executable = join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  return new Promise(resolve => {
    execFile(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(windowsQuery, 'utf16le').toString('base64')],
      { windowsHide: true, shell: false, timeout: 5000, maxBuffer: 4096, encoding: 'utf8',
        // Add-Type compiles into the temp directory; a sterile service environment may define
        // neither TEMP nor TMP, so fall back to the system Temp folder rather than the Windows folder.
        env: { SystemRoot: root, WINDIR: root, TEMP: process.env.TEMP || process.env.TMP || join(root, "Temp"),
          TMP: process.env.TMP || process.env.TEMP || join(root, "Temp"),
          PATH: join(root, 'System32'), PSModulePath: join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') } }, (error, stdout, stderr) => {
        if (error || stderr) { resolve(null); return; }
        try { const result: unknown = JSON.parse(stdout); resolve(validDomain(result) && result.platform === 'win32'
          ? { platform: 'win32', bootId: result.bootId, siloId: result.siloId } : null); }
        catch { resolve(null); }
      });
  });
}
async function queryProcessDomain(): Promise<ProcessDomain | null> {
  if (process.platform === 'win32') return windowsDomain();
  if (process.platform !== 'linux') return null;
  try {
    const bootId = (await fs.readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
    const namespace = await fs.stat('/proc/self/ns/pid', { bigint: true });
    const result: ProcessDomain = { platform: 'linux', bootId, pidNamespace: `${namespace.dev}:${namespace.ino}` };
    return validDomain(result) ? result : null;
  } catch { return null; }
}

let currentDomain: Promise<ProcessDomain | null> | undefined;
export function ownProcessDomain(): Promise<ProcessDomain | null> {
  return currentDomain ??= queryProcessDomain();
}
