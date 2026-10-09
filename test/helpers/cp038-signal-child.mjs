import { writeFileSync } from 'node:fs';
import { fixture, oldId } from './cp038-online.js';
import { LndError } from '../../src/errors.js';
import { handlers } from '../../src/commands/handlers.js';
import { main } from '../../src/cli.js';
import { run as bake } from '../../src/commands/bake/index.js';
import { run as rotate } from '../../src/commands/rotate.js';
import { run as revoke } from '../../src/commands/revoke.js';

const [mode, point, marker] = process.argv.slice(2);
const f = fixture();
const pause = async id => {
  writeFileSync(marker, JSON.stringify({ registry: f.registry, out: f.out, oldId: String(oldId),
    id: id === undefined ? null : String(id), ids: f.lnd.ids.map(String), point }));
  process.send?.({ kind: 'boundary', marker });
  await new Promise((_, reject) => {
    const deadline = setTimeout(() => reject(new LndError(4, 'transport', 'paused operation deadline')), 4000);
    // A cooperatively completed command must not be kept alive by the test fault timer.
    deadline.unref();
  });
};
// Windows does not deliver catchable POSIX signals with child.kill(). Feed the signal
// event over IPC there; POSIX uses an actual OS signal after the same marker.
process.on('message', message => {
  if (message?.kind === 'signal') process.emit(message.signal);
});
if (mode === 'bake' || mode === 'stage') {
  if (point === 'before') {
    const original = f.lnd.listMacaroonIds.bind(f.lnd);
    f.lnd.listMacaroonIds = async () => { const ids = await original(); await pause(); return ids; };
  } else f.lnd.onBake = pause;
} else {
  const original = f.lnd.deleteMacaroonId.bind(f.lnd);
  f.lnd.deleteMacaroonId = async id => {
    if (point === 'before') await pause(id);
    const result = await original(id);
    if (point === 'after') await pause(id);
    return result;
  };
}
let args;
if (mode === 'bake') { f.save([]); args = ['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags]; handlers.bake = values => bake(values, f.deps); }
else if (mode === 'stage') { args = ['Alice', '--out', f.out, ...f.flags]; handlers.rotate = values => rotate(values, f.deps); }
else if (mode === 'finish') { f.save([f.old, f.next]); args = ['Alice', '--finish', '--yes', ...f.flags]; handlers.rotate = values => rotate(values, f.deps); }
else { args = ['Alice', '--yes', ...f.flags]; handlers.revoke = values => revoke(values, f.deps); }
const command = mode === 'stage' || mode === 'finish' ? 'rotate' : mode;
process.exitCode = await main([command, ...args, '--json']);
process.disconnect?.();
