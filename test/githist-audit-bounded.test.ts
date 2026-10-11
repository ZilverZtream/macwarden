import { expect, it } from 'vitest';
import { BoundedFileError, readBoundedFile, readPlainFile, type BoundedReadIO } from '../src/bounded-file.js';

// Pre-1.4 audit, bounded reads: device and inode are compared exactly (Windows file indexes
// exceed 2^53), a failed close never replaces the read's own error, and a caller can refuse
// a resolved target that is not local before it is stat'ed or opened.
const BASE = 2n ** 60n;

/** A file system whose path resolves to /real and whose stat answers numbers unless asked for bigints. */
function fakeIo(options: { checkedIno: bigint; openedIno: bigint; closeFails?: boolean; readFails?: boolean }) {
  const calls: string[] = [];
  const stats = (ino: bigint, bigint: boolean) => ({
    isFile: () => true, isSymbolicLink: () => false, dev: bigint ? 7n : 7, ino: bigint ? ino : Number(ino), size: bigint ? 3n : 3,
  });
  const io = {
    realpath: async (path: string) => { calls.push(`realpath ${path}`); return '/real'; },
    stat: async (path: string, opts?: { bigint?: boolean }) => { calls.push(`stat ${path}`); return stats(options.checkedIno, !!opts?.bigint); },
    lstat: async (path: string, opts?: { bigint?: boolean }) => { calls.push(`lstat ${path}`); return stats(options.checkedIno, !!opts?.bigint); },
    open: async (path: string) => {
      calls.push(`open ${path}`);
      return {
        stat: async (opts?: { bigint?: boolean }) => stats(options.openedIno, !!opts?.bigint),
        read: async (buffer: Buffer, offset: number, length: number, position: number) => {
          if (options.readFails) throw Object.assign(new Error('read failed'), { code: 'EIO' });
          const data = Buffer.from('abc').subarray(position, position + length);
          data.copy(buffer, offset);
          return { bytesRead: data.length, buffer };
        },
        close: async () => { if (options.closeFails) throw new Error('close failed'); },
      };
    },
  };
  return { io: io as unknown as BoundedReadIO & Parameters<typeof readPlainFile>[1], calls };
}

it('githist-audit/bounded a file index differing only above 2^53 is a different file', async () => {
  const replaced = fakeIo({ checkedIno: BASE + 1n, openedIno: BASE });
  await expect(readBoundedFile('/x', replaced.io)).rejects.toThrow(new BoundedFileError('file changed'));
  const same = fakeIo({ checkedIno: BASE + 1n, openedIno: BASE + 1n });
  await expect(readBoundedFile('/x', same.io)).resolves.toEqual(Buffer.from('abc'));
});

it('githist-audit/bounded a failing close does not replace the read error or a successful read', async () => {
  const failing = fakeIo({ checkedIno: 1n, openedIno: 1n, closeFails: true, readFails: true });
  await expect(readBoundedFile('/x', failing.io)).rejects.toThrow('read failed');
  await expect(readPlainFile('/x', failing.io, 16)).rejects.toThrow('read failed');
  const closing = fakeIo({ checkedIno: 1n, openedIno: 1n, closeFails: true });
  await expect(readBoundedFile('/x', closing.io)).resolves.toEqual(Buffer.from('abc'));
});

it('githist-audit/bounded a resolved target the caller does not accept as local is refused before stat or open', async () => {
  const { io, calls } = fakeIo({ checkedIno: 1n, openedIno: 1n });
  await expect(readBoundedFile('/x', io, 16, { local: target => target !== '/real' }))
    .rejects.toThrow(new BoundedFileError('not a local file'));
  expect(calls).toEqual(['realpath /x']);
});
