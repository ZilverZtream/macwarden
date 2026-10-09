import { fixtureTopology } from '../fixture/topology.mjs';
import { connect } from 'node:http2';
import { readFileSync } from 'node:fs';
import { FixtureInvalidError } from './fixture-invalid.mjs';

// Pinned lncli has no HtlcInterceptor command. Probe the actual streaming RPC
// independently with native HTTP/2; no macwarden adapter or permission check.
// Credentials enter only by registered path, and never leave this function.
export function probeHtlcInterceptor(certPath, credentialPath) {
  return new Promise((resolve, reject) => {
    const session = connect(`https://localhost:${fixtureTopology().grpcPort}`, { ca: readFileSync(certPath) });
    let finished = false;
    let stream;
    let grpcStatus;
    let grpcMessage = '';
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      stream?.close();
      session.destroy();
      if (error) reject(new FixtureInvalidError(error));
      else resolve(result);
    };
    const timer = setTimeout(() => finish('HtlcInterceptor probe timed out'), 10_000);
    session.on('error', () => finish('HtlcInterceptor fixture connection unavailable'));
    session.on('connect', () => {
      stream = session.request({ ':method': 'POST', ':path': '/routerrpc.Router/HtlcInterceptor',
        'content-type': 'application/grpc', te: 'trailers',
        macaroon: readFileSync(credentialPath).toString('hex') });
      const observe = headers => {
        if (headers['grpc-status'] !== undefined) grpcStatus = Number(headers['grpc-status']);
        if (headers['grpc-message'] !== undefined) grpcMessage = String(headers['grpc-message']);
      };
      stream.on('response', observe);
      stream.on('trailers', observe);
      stream.on('data', () => { /* Consume frames; never report arbitrary response content. */ });
      stream.on('error', () => finish('HtlcInterceptor fixture stream unavailable'));
      stream.on('end', () => {
        if (grpcStatus !== undefined && grpcStatus !== 0 &&
            /permission|not authorized|not permitted/i.test(grpcMessage)) finish(null, 'permission-denied');
        else finish(null, 'unexpected');
      });
      // One uncompressed empty protobuf message; the server authenticates the
      // stream before delivering any HTLC or interpreting a resolution.
      stream.end(Buffer.from([0, 0, 0, 0, 0]));
    });
  });
}
