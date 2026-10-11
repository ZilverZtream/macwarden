// One worker thread of leakScans (scripts/leak-check.mjs). It receives the sentinel
// snapshot from the parent rather than re-reading the sentinel files, so every worker
// checks against exactly the population the parent enumerated.
import { parentPort, workerData } from 'node:worker_threads';
import { leakScanWorker } from './leak-check.mjs';

leakScanWorker(workerData, message => parentPort.postMessage(message));
