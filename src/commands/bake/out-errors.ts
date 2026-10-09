/** A reservation failure whose message the commands show after "cannot reserve output file". */
export class OutputReserveError extends Error {
  constructor(message: string) { super(message); this.name = 'OutputReserveError'; }
}

/** The text a command prints for a failed output reservation. */
export function reserveFailure(error: unknown, fallback = 'cannot reserve output file'): string {
  return error instanceof OutputReserveError ? `${fallback}: ${error.message}` : fallback;
}
