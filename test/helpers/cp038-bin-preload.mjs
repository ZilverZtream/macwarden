import { fixture } from './cp038-online.js';
import { handlers } from '../../src/commands/handlers.js';
import { run } from '../../src/commands/bake/index.js';
const f = fixture(); f.save([]);
f.lnd.onBake = () => { process.emit('uncaughtException', new Error('private process-event detail')); };
handlers.bake = args => run(args, f.deps);
process.argv.splice(2, process.argv.length - 2, 'bake', '--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags, '--json');
