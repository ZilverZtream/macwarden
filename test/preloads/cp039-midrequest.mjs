import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import { writeFileSync } from 'node:fs';

const original = https.request;
https.request = function (...args) {
  const request = Reflect.apply(original, https, args);
  writeFileSync(process.env.MACWARDEN_CP039_TRACE, 'request-entered');
  const options = args[0];
  const credential = String(options?.headers?.['Grpc-Metadata-macaroon'] ?? '');
  process.nextTick(() => process.emit('uncaughtException', new Error(`peer failed ${credential}`)));
  return request;
};
syncBuiltinESMExports();
