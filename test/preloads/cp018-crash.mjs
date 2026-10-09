import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';

// Keep the real request. Force an unexpected process error only after it begins.
const request = https.request;
https.request = function (...args) {
  const pending = request.apply(this, args);
  queueMicrotask(() => { void Promise.reject(new Error(process.env.MACWARDEN_CRASH_MARKER || 'crash')); });
  return pending;
};
syncBuiltinESMExports();
