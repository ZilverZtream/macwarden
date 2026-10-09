import type { LndAdapter } from '../../src/lnd/index.js';

export function adapter(overrides: Partial<LndAdapter>): LndAdapter {
  const unexpected = (): never => { throw new Error('Unexpected adapter call outside this test scenario'); };
  return { getInfo: async () => unexpected(), listMacaroonIds: async () => unexpected(),
    listPermissions: async () => unexpected(), bakeMacaroon: async () => unexpected(),
    deleteMacaroonId: async () => unexpected(), checkMacaroon: async () => unexpected(), ...overrides };
}
