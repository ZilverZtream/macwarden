import { vi } from 'vitest';

export async function captureMain(main: (argv: string[]) => Promise<number>, argv: string[]) {
  let stdout = '';
  let stderr = '';
  const out = vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  }) as typeof process.stdout.write);
  const err = vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  }) as typeof process.stderr.write);
  const exit = vi.spyOn(process, 'exit').mockImplementation((() => {
    throw new Error('process.exit called from main');
  }) as typeof process.exit);
  try {
    const code = await main(argv);
    return { code, stdout, stderr, exitCalls: exit.mock.calls.length };
  } finally {
    out.mockRestore();
    err.mockRestore();
    exit.mockRestore();
  }
}
