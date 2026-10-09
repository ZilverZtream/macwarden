import type { OutputResult } from '../output/index.js';
import { inspect } from './inspect.js';
import { run as scan } from './scan.js';
import { inventory } from './inventory.js';
import { bake } from './bake/index.js';
import { revoke } from './revoke.js';
import { rotate } from './rotate.js';
import { attenuate } from './attenuate.js';
import { watch } from './watch.js';
import { recommend } from './recommend.js';
import { respond } from './respond.js';
import { verify } from './verify.js';
import { reconcile } from './reconcile.js';

export type CommandHandler = (args: string[]) => Promise<OutputResult & { exitCode?: number }>;

export const handlers: Record<string, CommandHandler> = { inspect, scan, inventory, bake, revoke, rotate, attenuate, watch, recommend, respond, verify, reconcile };
