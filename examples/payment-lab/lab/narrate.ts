/**
 * Console narration for setup and the scenarios. A verdict is a list of
 * checks, each computed from node state or durable records; the run passes
 * only if every check passes.
 */

const useColor = process.stdout.isTTY === true && process.env.NO_COLOR === undefined;
const paint = (code: string, text: string): string => (useColor ? `\u001b[${code}m${text}\u001b[0m` : text);

export function title(text: string): void {
  process.stdout.write(`\n${paint('1', text)}\n${'='.repeat(text.length)}\n`);
}

export function step(text: string): void {
  process.stdout.write(`\n${paint('1;36', `> ${text}`)}\n`);
}

export function say(text: string): void {
  process.stdout.write(`  ${text}\n`);
}

export function fact(label: string, value: string | number | bigint | boolean): void {
  process.stdout.write(`  ${paint('2', `${label}:`)} ${String(value)}\n`);
}

export function command(text: string): void {
  process.stdout.write(`  ${paint('2', '$')} ${text}\n`);
}

export function warn(text: string): void {
  process.stdout.write(`  ${paint('33', `! ${text}`)}\n`);
}

export class Verdict {
  readonly #checks: { name: string; ok: boolean; detail: string }[] = [];
  readonly #scenario: string;

  constructor(scenario: string) {
    this.#scenario = scenario;
  }

  check(name: string, ok: boolean, detail: string): boolean {
    this.#checks.push({ name, ok, detail });
    process.stdout.write(`  ${ok ? paint('32', 'ok  ') : paint('31', 'FAIL')} ${name}: ${detail}\n`);
    return ok;
  }

  /** Prints the verdict and returns the process exit code. */
  finish(): number {
    const failed = this.#checks.filter(item => !item.ok);
    const passed = this.#checks.length > 0 && failed.length === 0;
    process.stdout.write(`\n${paint('1', `VERDICT ${this.#scenario}: ${passed ? paint('32', 'PASS') : paint('31', 'FAIL')}`)}`
      + ` (${this.#checks.length - failed.length}/${this.#checks.length} checks passed, computed from node state and durable records)\n`);
    for (const item of failed) process.stdout.write(`  failed: ${item.name}: ${item.detail}\n`);
    return passed ? 0 : 1;
  }
}

/** Polls `probe` until it returns a value, failing after `timeoutMs`. Waits on real state, never a fixed time. */
export async function waitUntil<T>(description: string, probe: () => Promise<T | undefined> | T | undefined,
  options: { timeoutMs: number; intervalMs?: number }): Promise<T> {
  const deadline = Date.now() + options.timeoutMs;
  const interval = options.intervalMs ?? 1000;
  let lastError: unknown;
  for (;;) {
    try {
      const value = await probe();
      if (value !== undefined) return value;
    } catch (error) {
      lastError = error;
    }
    if (Date.now() >= deadline) {
      const reason = lastError instanceof Error ? `; last error: ${lastError.message}` : '';
      throw new Error(`timed out after ${options.timeoutMs} ms waiting for ${description}${reason}`);
    }
    await new Promise(resolve => setTimeout(resolve, Math.min(interval, Math.max(0, deadline - Date.now()))));
  }
}
