import { expect, it } from 'vitest';
import { lockOwnerGone } from '../src/commands/watch.js';
import type { ProcessDomain } from '../src/registry/process-domain.js';

// Fresh audit (2026-10-08): a lock left by a crashed container's watch (PID 1) was read as
// "alive" by the restarted container's watch, also PID 1, so canary guarding never resumed.
const boot = '36fab8a9-2ae9-11f0-b7c7-8a889eea68a4';
const otherBoot = '11111111-2222-4333-8444-555555555555';
const linux = (bootId = boot, pidNamespace = '4:4026531836'): ProcessDomain => ({ platform: 'linux', bootId, pidNamespace });
const alive = () => undefined;
const dead = () => { throw Object.assign(new Error('gone'), { code: 'ESRCH' }); };
const denied = () => { throw Object.assign(new Error('perm'), { code: 'EPERM' }); };

it('WATCH/lock-owner a lock naming this process\'s own PID on the same host is stale (restarted container, PID 1 again)', () => {
  expect(lockOwnerGone({ pid: 1, hostname: 'box' }, 'box', 1, linux(), alive)).toBe(true);
  expect(lockOwnerGone({ pid: 1, hostname: 'box', domain: linux() }, 'box', 1, linux(), alive)).toBe(true);
});

it('WATCH/lock-owner an owner from an earlier boot is gone even when its PID is alive now', () => {
  expect(lockOwnerGone({ pid: 4242, hostname: 'box', domain: linux(otherBoot) }, 'box', 7, linux(), alive)).toBe(true);
});

it('WATCH/lock-owner uncertain owners keep the lock: other host, other namespace, live or unprobeable PID', () => {
  expect(lockOwnerGone({ pid: 4242, hostname: 'other', domain: linux() }, 'box', 7, linux(), dead)).toBe(false);
  // Same boot, another PID namespace: a dead-looking PID here proves nothing about the owner.
  expect(lockOwnerGone({ pid: 4242, hostname: 'box', domain: linux(boot, '4:4026532000') }, 'box', 7, linux(), dead)).toBe(false);
  expect(lockOwnerGone({ pid: 4242, hostname: 'box', domain: linux() }, 'box', 7, linux(), alive)).toBe(false);
  expect(lockOwnerGone({ pid: 4242, hostname: 'box', domain: linux() }, 'box', 7, linux(), denied)).toBe(false);
  expect(lockOwnerGone({ pid: 0, hostname: 'box' }, 'box', 7, null, dead)).toBe(false);
});

it('WATCH/lock-owner a dead owner in the same domain, or a legacy record without a domain, is gone', () => {
  expect(lockOwnerGone({ pid: 4242, hostname: 'box', domain: linux() }, 'box', 7, linux(), dead)).toBe(true);
  expect(lockOwnerGone({ pid: 4242, hostname: 'box' }, 'box', 7, linux(), dead)).toBe(true);
});
