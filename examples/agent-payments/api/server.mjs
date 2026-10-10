// The paid API behind Aperture. It knows nothing about Lightning: Aperture only
// forwards requests that carry a paid L402 token.
import { createServer } from 'node:http';

const forecast = {
  location: 'Regtest Harbour',
  hours: [
    { hour: '06:00', windKnots: 12, direction: 'SW' },
    { hour: '09:00', windKnots: 15, direction: 'SW' },
    { hour: '12:00', windKnots: 18, direction: 'W' },
  ],
};

const server = createServer((request, response) => {
  // Health check for Docker; Aperture forwards only /api/ paths, so it is not reachable from outside.
  if (request.method === 'GET' && request.url === '/healthz') {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('ok');
    return;
  }
  if (request.method === 'GET' && request.url === '/api/forecast') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(forecast));
    return;
  }
  response.writeHead(404, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ error: 'not found' }));
});

server.listen(8000, '0.0.0.0');
process.on('SIGTERM', () => server.close(() => process.exit(0)));
