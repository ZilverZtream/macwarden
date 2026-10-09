export class FixtureInvalidError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FixtureInvalidError';
  }
}
