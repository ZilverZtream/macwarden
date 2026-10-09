import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

const blocked = () => { throw new Error('offline inspect attempted network access'); };
for (const target of [net, http, https]) {
  for (const key of ['connect', 'createConnection', 'request', 'get']) {
    if (typeof target[key] === 'function') target[key] = blocked;
  }
}
syncBuiltinESMExports();
