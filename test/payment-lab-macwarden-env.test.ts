import { expect, it } from 'vitest';

// Audit 1.3.2: the lab removed NODE_OPTIONS, NODE_DEBUG and MACWARDEN_* from macwarden's
// environment by exact case, but macwarden reads the Node variables in any case (a Windows
// variable keeps the case it was set with), so `node_options` made the lab's bake fail at B2.
// Loaded by a computed specifier, as test/helpers/payment-lab-modules.ts loads the lab.
type Lab = { macwardenEnv(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv };
const relative = 'lab/macwarden.ts';
const { macwardenEnv } = await import(/* @vite-ignore */ `../examples/payment-lab/${relative}`) as Lab;

it('LAB/macwarden-env Node diagnostics and connection variables are removed in any case', () => {
  const env = macwardenEnv({ node_options: '--x', Node_Debug: 'tls', NODE_OPTIONS: '--y', macwarden_lnd_rest: 'h',
    MACWARDEN_TLS_CERT: 'c', PATH: '/bin', Path: 'C:\\bin', HOME: '/home/u' });
  expect(env).toEqual({ PATH: '/bin', Path: 'C:\\bin', HOME: '/home/u' });
});
