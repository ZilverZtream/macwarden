import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, lstatSync, statSync, existsSync } from 'node:fs';
import { resolve, relative, dirname, basename, join, sep, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

// Same leftmost-greedy matches as /W+(?:SW+)+={0,2}/g for the three grouped base64
// shapes, in linear time (the regular expressions backtrack quadratically over long
// unseparated runs). Mirrors src/grouped-runs.ts; test/grouped-runs.test.ts checks both.
export function groupedBase64Runs(text, shape) {
  const digit = character => /^[A-Za-z0-9+/]$/.test(character);
  const word = shape === 'dash' ? character => digit(character) || character === '_'
    : shape === 'underscore' ? digit : character => digit(character) || character === '_' || character === '-';
  const separator = shape === 'dash' ? character => character === '-'
    : shape === 'underscore' ? character => character === '_' : character => !/^[A-Za-z0-9+/_=\s\\-]$/.test(character);
  const runs = [];
  let at = 0;
  while (at < text.length) {
    if (!word(text[at])) { at++; continue; }
    const start = at;
    while (at < text.length && word(text[at])) at++;
    let end = at, groups = 1;
    while (end + 1 < text.length && separator(text[end]) && word(text[end + 1])) {
      end++;
      while (end < text.length && word(text[end])) end++;
      groups++;
    }
    if (groups === 1) continue;
    let padding = 0;
    while (padding < 2 && text[end + padding] === '=') padding++;
    runs.push(text.slice(start, end + padding));
    at = end + padding;
  }
  return runs;
}

function filesUnder(path, rejectLinks = false) {
  let stat;
  try { stat = lstatSync(path); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  if (stat.isSymbolicLink()) {
    if (rejectLinks) throw new Error('linked artifact path');
    return [];
  }
  if (!stat.isDirectory()) return stat.isFile() ? [path] : [];
  return readdirSync(path).flatMap(name => filesUnder(join(path, name), rejectLinks));
}

function globPattern(glob) {
  let pattern = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') { pattern += '(?:.*/)?'; i += 2; }
      else { pattern += '.*'; i++; }
    }
    else if (c === '*') pattern += '[^/]*';
    else if (c === '?') pattern += '[^/]';
    else pattern += c.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
  }
  return new RegExp(`^${pattern}$`);
}

function variants(bytes) {
  const base64 = bytes.toString('base64');
  const base64url = bytes.toString('base64url');
  return [
    ['utf8', bytes.toString('utf8')], ['latin1', bytes.toString('latin1')],
    ['hex-lower', bytes.toString('hex')], ['hex-upper', bytes.toString('hex').toUpperCase()],
    ['base64-padded', base64], ['base64-unpadded', base64.replace(/=+$/, '')],
    ['base64url-padded', base64.replace(/\+/g, '-').replace(/\//g, '_')],
    ['base64url-unpadded', base64url],
    // Case folding (for example a URL hostname) keeps most of a base64 value's bits.
    ['base64-case-folded', base64.replace(/=+$/, '').toLowerCase()],
    ['base64url-case-folded', base64url.toLowerCase()],
    ['base32', base32(bytes)],
    ['base32-lower', base32(bytes).toLowerCase()],
  ].filter(([, value]) => value.length > 0);
}

function base32(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let accumulator = 0, bits = 0, text = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; text += alphabet[(accumulator >>> bits) & 31]; }
  }
  if (bits) text += alphabet[(accumulator << (5 - bits)) & 31];
  return text;
}

function hexStreams(text) {
  text = text.replace(/0x(?=[0-9a-f]{2})/gi, '');
  const nibble = code => code >= 48 && code <= 57 ? code - 48
    : code >= 65 && code <= 70 ? code - 55
      : code >= 97 && code <= 102 ? code - 87 : -1;
  const separatorEnd = at => {
    const char = text[at];
    if (char !== undefined && char !== '\\' && /[^0-9A-Za-z]/u.test(char)) return at + 1;
    if (char !== '\\') return at;
    if (text[at + 1] !== undefined && 'trnfv'.includes(text[at + 1])) return at + 2;
    if (text[at + 1] === 'u' &&
        ['0009', '000a', '000b', '000c', '000d', '0020'].includes(
          text.slice(at + 2, at + 6).toLowerCase())) return at + 6;
    return at;
  };

  const stream = capacity => ({ bytes: Buffer.allocUnsafe(capacity),
    length: 0, start: 0, ends: [] });
  const ordinary = stream(Math.floor(text.length / 2));
  // Odd groups contribute both their ordinary and shifted pairs here.
  const shifted = stream(text.length);
  const finish = stream => {
    // The separated-hex recognizer has always required at least two bytes.
    // Short segments cannot match; dropping them retains the same boundaries.
    if (stream.length - stream.start >= 2) stream.ends.push(stream.length);
    else stream.length = stream.start;
    stream.start = stream.length;
  };
  let shiftedActive = false;
  for (let at = 0; at < text.length;) {
    if (nibble(text.charCodeAt(at)) < 0) {
      at++;
      continue;
    }

    const start = at;
    while (at < text.length && nibble(text.charCodeAt(at)) >= 0) at++;
    // Keep the ordinary pairs through an odd final group. A shifted stream
    // starts one nibble into an odd group and continues through later groups;
    // another odd group ends that stream only after its ordinary pairs.
    const odd = (at - start) % 2 !== 0;
    for (let pair = start; pair + 1 < at; pair += 2) {
      const byte = nibble(text.charCodeAt(pair)) * 16 + nibble(text.charCodeAt(pair + 1));
      ordinary.bytes[ordinary.length++] = byte;
      if (shiftedActive) shifted.bytes[shifted.length++] = byte;
    }
    if (odd) {
      finish(shifted);
      shiftedActive = true;
      for (let pair = start + 1; pair + 1 < at; pair += 2) {
        const byte = nibble(text.charCodeAt(pair)) * 16 + nibble(text.charCodeAt(pair + 1));
        shifted.bytes[shifted.length++] = byte;
      }
      finish(ordinary);
    }

    const beforeSeparator = at;
    while (at < text.length) {
      const end = separatorEnd(at);
      if (end === at) break;
      at = end;
    }
    if (at === beforeSeparator || at >= text.length || nibble(text.charCodeAt(at)) < 0) {
      finish(ordinary);
      finish(shifted);
      shiftedActive = false;
    }
  }
  finish(ordinary);
  finish(shifted);
  return [ordinary, shifted].map(({ bytes, length, ends }) =>
    ({ bytes: bytes.subarray(0, length), ends: Uint32Array.from(ends) }));
}

function streamIncludes(streams, source) {
  for (const { bytes, ends, starts, finishes } of streams) {
    for (let at = bytes.indexOf(source); at !== -1; at = bytes.indexOf(source, at + 1)) {
      // Concatenating segments lets each source use native search. Reject any
      // match crossing a reset; no delimiter byte can safely stand for a reset.
      let low = 0, high = ends.length;
      while (low < high) {
        const mid = Math.floor((low + high) / 2);
        if (ends[mid] <= at) low = mid + 1;
        else high = mid;
      }
      if (at + source.length <= ends[low] &&
          (!starts || starts[at]) && (!finishes || finishes[at + source.length - 1])) return true;
    }
  }
  return false;
}

function decimalStream(text) {
  const streams = [];
  const runs = /\d{1,3}(?:[^0-9A-Za-z\\]{1,3}\d{1,3})+/g;
  for (let run; (run = runs.exec(text)) !== null;) {
    const values = run[0].split(/[^0-9]+/).map(Number);
    for (let segmentStart = 0; segmentStart < values.length;) {
      let segmentEnd = segmentStart;
      while (segmentEnd < values.length && values[segmentEnd] <= 255) segmentEnd++;
      if (segmentEnd > segmentStart) {
        const bytes = Buffer.from(values.slice(segmentStart, segmentEnd));
        streams.push({ bytes, ends: Uint32Array.of(bytes.length) });
      }
      segmentStart = segmentEnd + 1;
    }
  }
  return streams;
}

function recoveredText(text) {
  for (let round = 0; round < 2; round++) {
    text = text.replace(/%u([0-9a-f]{4})|&#(?:x([0-9a-f]{1,4})|([0-9]{1,5}));/gi,
      (match, unicode, hex, decimal) => {
        const value = parseInt(unicode ?? hex ?? decimal, decimal ? 10 : 16);
        return value <= 255 ? String.fromCharCode(value) : match;
      });
    text = text.replace(/\\(?:u([0-9a-f]{4})|x([0-9a-f]{2})|([0-7]{1,3})|([\\"/bfnrt]))/gi,
      (_match, unicode, hex, octal, simple) => unicode || hex || octal
        ? String.fromCharCode(parseInt(unicode ?? hex ?? octal, octal ? 8 : 16))
        : ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[simple] ?? simple));
  }
  return text;
}

function preparedSource(source) {
  const hex = source.toString('hex');
  const latin1 = source.toString('latin1');
  const utf16le = Buffer.from(latin1, 'utf16le');
  const base64 = source.toString('base64');
  const base64url = source.toString('base64url');
  const base64Forms = [...new Set([base64, base64.replace(/=+$/, ''),
    base64.replace(/\+/g, '-').replace(/\//g, '_'), base64url])];
  return {
    source, hex, latin1, base64, base64url, base64Forms,
    // Text encodings as bytes, for a second layer: base64 or hex of this text.
    textForms: [...new Set([hex, hex.toUpperCase(), ...base64Forms])].map(form => Buffer.from(form)),
    utf16le, utf16be: Buffer.from(utf16le).swap16(),
    percentBytes: hex.replace(/../g, byte => `%${byte}`),
    escapedBytes: hex.replace(/../g, byte => `\\x${byte}`),
    decimalMinLength: [...source].reduce((length, byte) => length + String(byte).length, source.length + 1),
  };
}

function preparedData(data) {
  const utf16 = Buffer.from(data.subarray(0, data.length - data.length % 2));
  const recovered = [data.toString('utf8'), utf16.toString('utf16le'),
    Buffer.from(utf16).swap16().toString('utf16le')].map(recoveredText);
  const text = recovered.join('\n');
  // Zero-width characters split a value as invisibly as whitespace does.
  const compact = text.replace(/[\s\u200b-\u200d\u2060\ufeff]/g, '');
  // Two more views of split values, each one linear pass: adjacent string literals
  // joined ("ab" + "cd", ["ab", "cd"]), and the last token of every line joined
  // (wrapped output behind a per-line log prefix such as a timestamp).
  const joined = text.replace(/(["'`])(?=([\s\u200b-\u200d\u2060\ufeff]*))\2[,+]?(?=([\s\u200b-\u200d\u2060\ufeff]*))\3\1/g, '')
    .replace(/[\s\u200b-\u200d\u2060\ufeff]/g, '');
  const lastToken = line => {
    let end = line.length;
    while (end > 0 && /\s/.test(line[end - 1])) end--;
    let start = end;
    while (start > 0 && !/\s/.test(line[start - 1])) start--;
    return line.slice(start, end);
  };
  const tails = text.split('\n').map(lastToken).join('');
  const percent = text.replace(/%([0-9a-f]{2})/gi, (_, digits) => String.fromCharCode(parseInt(digits, 16)));
  let separated, decimal;
  // Native byte searches retain exact UTF-8 representations of the recovered
  // strings. Keep only the decimal/hex parser text on the JavaScript heap;
  // several full-size normalized strings otherwise exhaust it on real logs.
  return { data, recovered: recovered.map(text => Buffer.from(text)), text,
    lower: Buffer.from(text.toLowerCase()), compact: Buffer.from(compact),
    compactLower: Buffer.from(compact.toLowerCase()),
    percent: Buffer.from(percent), percentLower: Buffer.from(percent.toLowerCase()),
    splitViews: [Buffer.from(joined), Buffer.from(tails)],
    hexStreams: () => separated ??= hexStreams(text),
    decimalStream: () => decimal ??= decimalStream(text),
    base64Runs: [
      ...[text, joined, tails].flatMap(view => view.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) ?? []),
      ...groupedBase64Runs(text, 'dash').map(run => run.replaceAll('-', '')),
      ...groupedBase64Runs(text, 'underscore').map(run => run.replaceAll('_', '')),
      ...groupedBase64Runs(text, 'other').filter(run => {
        // Only regular groups (equal, multiple of four) as real grouping produces.
        const lengths = run.replace(/=+$/, '').split(/[^A-Za-z0-9+/_-]/).map(group => group.length);
        return lengths[0] % 4 === 0 && lengths.slice(0, -1).every(length => length === lengths[0]) && lengths.at(-1) <= lengths[0];
      }).map(run => run.replace(/[^A-Za-z0-9+/_=-]/g, '')),
    ].flatMap(run => [0, 1, 2, 3].map(phase => Buffer.from(run.slice(phase), 'base64url'))) };
}

function alternateEncoding(data, source, state = preparedSource(source), input = preparedData(data)) {
  const { recovered, text, lower, compact, compactLower, percent, percentLower, base64Runs } = input;
  const { hex, base64, base64url, latin1 } = state;
  if (recovered.some(text => text.includes(latin1))) return 'recovered escaped bytes';
  if (lower.includes(hex)) return 'mixed-case hex';
  if (text.length >= state.decimalMinLength && streamIncludes(input.decimalStream(), source)) return 'decimal byte array';
  if (source.length >= 2 && text.length >= source.length * 2 &&
      streamIncludes(input.hexStreams(), source)) return 'separated hex';
  if (compactLower.includes(hex)) return 'wrapped hex';
  if (state.base64Forms.some(form => compact.includes(form))) return 'wrapped base64';
  if (percentLower.includes(hex)) return 'percent-encoded hex';
  if (percent.includes(base64) || percent.includes(base64url)) return 'percent-encoded base64';
  if (state.base64Forms.some(form => compactLower.includes(form.replace(/=+$/, '').toLowerCase()) ||
    percentLower.includes(form.replace(/=+$/, '').toLowerCase()))) return 'case-folded base64';
  if (lower.includes(state.percentBytes)) return 'percent-encoded bytes';
  if (lower.includes(state.escapedBytes)) return 'escaped bytes';
  if (data.includes(state.utf16le) || data.includes(state.utf16be)) return 'utf-16 bytes';
  // Decode each maximal base64 run once, preserving offset recognition.
  if (base64Runs.some(run => run.includes(source))) return 'offset base64';
  if (input.splitViews.some(view => state.textForms.some(form => view.includes(form)))) return 'split literals';
  // A second layer: base64 of the hex or base64 text, or hex of the base64 text.
  if (base64Runs.some(run => state.textForms.some(form => run.includes(form)))) return 'base64 of a text encoding';
  if (text.length >= source.length * 2 && state.textForms.some(form => streamIncludes(input.hexStreams(), form)))
    return 'hex of a text encoding';
  return null;
}

function preparedMatcherGroup(states) {
  const matcher = values => {
    const literals = [...new Set(values.map(bytes => bytes.toString('latin1')))];
    const pattern = new RegExp(literals.map(value => value.replace(/[|\\{}()[\]^$+*?.]/g, '\\$&')).join('|'));
    return bytes => pattern.test(bytes.toString('latin1'));
  };
  const raw = matcher(states.map(state => state.source));
  const encoded = matcher(states.flatMap(state => [
    ...state.variants.map(variant => variant.bytes), state.utf16le, state.utf16be,
    Buffer.from(state.percentBytes), Buffer.from(state.escapedBytes),
  ]));
  return input => {
    // These literal alternatives contain every full registered credential.
    // This filter may admit a match across parser boundaries; the detailed
    // checks below still enforce all boundaries and choose the encoding.
    if (raw(input.data) || encoded(input.data)) return true;
    if ([...input.recovered, input.lower, input.compact, input.compactLower,
      input.percent, input.percentLower, ...input.splitViews].some(encoded)) return true;
    if (input.hexStreams().some(stream => raw(stream.bytes) || encoded(stream.bytes)) ||
        input.decimalStream().some(stream => raw(stream.bytes))) return true;
    return input.base64Runs.some(run => raw(run) || encoded(run));
  };
}

const matcherGroups = new Map();
let matcherBytes = 0;
function preparedMatcher(states) {
  // A newly registered credential changes one small group rather than forcing
  // the engine to compile an ever-growing literal alternation from scratch.
  const groups = Array.from({ length: 32 }, () => []);
  for (const state of states) {
    let hash = 2166136261;
    for (const byte of state.source) hash = Math.imul(hash ^ byte, 16777619);
    groups[hash >>> 0 & 31].push(state);
  }
  const matchers = groups.filter(group => group.length).map(group => {
    const key = group.map(state => state.hex).join(':');
    const found = matcherGroups.get(key);
    if (found) return found.match;
    const match = preparedMatcherGroup(group);
    const size = group.reduce((size, state) => size + state.source.length * 256 + 4096, key.length * 2);
    const limit = 64 * 1_048_576;
    if (size <= limit) {
      while (matcherGroups.size >= 256 || matcherBytes + size > limit) {
        const oldest = matcherGroups.keys().next().value;
        matcherBytes -= matcherGroups.get(oldest).size;
        matcherGroups.delete(oldest);
      }
      matcherGroups.set(key, { match, size });
      matcherBytes += size;
    }
    return match;
  });
  return input => matchers.some(match => match(input));
}

function safePath(path, sources, state = preparedRedactor(sources)) {
  if (path === 'command output') return path;
  let safe = path;
  for (const { value, regex } of state.encoded) {
    safe = regex ? safe.replace(regex, '[redacted]') : safe.replaceAll(value, '[redacted]');
  }
  // Recognize the filename independently: hex-looking directory prefixes can
  // share separators with its encoding and change the byte alignment.
  const data = Buffer.from(safe);
  const input = preparedData(data);
  const nameData = Buffer.from(basename(safe));
  const nameInput = basename(safe) === safe ? input : preparedData(nameData);
  if (state.sources.some(source => alternateEncoding(data, source.source, source, input) ||
    alternateEncoding(nameData, source.source, source, nameInput))) return '[redacted path]';
  return safe;
}

function preparedRedactor(sources) {
  const states = sources.map(preparedCredential);
  return { sources: states,
    encoded: states.flatMap(state => state.redactions).sort((a, b) => b.value.length - a.value.length) };
}

const preparedCredentials = new Map();
let credentialBytes = 0;
function preparedCredential(source) {
  const key = source.toString('hex');
  const found = preparedCredentials.get(key);
  if (found) return found;
  const forms = variants(source);
  const state = { ...preparedSource(source),
    variants: forms.map(([encoding, value]) => ({ encoding, value,
      lower: value.toLowerCase(), bytes: Buffer.from(value, 'utf8') })),
    redactions: forms.map(([encoding, value]) => ({ value,
      regex: encoding.startsWith('hex-') ? new RegExp(value, 'gi') : null })),
    size: source.length * 256 + 4096 };
  const limit = 64 * 1_048_576;
  if (state.size <= limit) {
    while (preparedCredentials.size >= 4096 || credentialBytes + state.size > limit) {
      const oldest = preparedCredentials.keys().next().value;
      credentialBytes -= preparedCredentials.get(oldest).size;
      preparedCredentials.delete(oldest);
    }
    preparedCredentials.set(key, state);
    credentialBytes += state.size;
  }
  return state;
}

// Keys contain the complete bytes in their current order, never paths or file
// metadata. Callers must enumerate and read the sources before consulting this
// cache, so replacement, late registration and unreadable sources stay visible.
const sourceSnapshots = new Map();
let snapshotBytes = 0;
function preparedSnapshot(sources) {
  const key = sources.map(source => source.toString('hex')).join(':');
  const found = sourceSnapshots.get(key);
  if (found) return found;
  const states = sources.map(preparedCredential);
  const state = { states, possibleLeak: sources.length ? preparedMatcher(states) : null,
    redactor: preparedRedactor(sources),
    // Include buffers, string encodings, regex alternatives and per-source
    // overhead conservatively. Oversized snapshots receive uncached checks.
    size: sources.reduce((size, source) => size + source.length * 256 + 4096, key.length * 2) };
  const limit = 64 * 1_048_576;
  if (state.size <= limit) {
    while (sourceSnapshots.size >= 4 || snapshotBytes + state.size > limit) {
      const oldest = sourceSnapshots.keys().next().value;
      snapshotBytes -= sourceSnapshots.get(oldest).size;
      sourceSnapshots.delete(oldest);
    }
    sourceSnapshots.set(key, state);
    snapshotBytes += state.size;
  }
  return state;
}

/**
 * @typedef {object} SentinelOptions
 * @property {string} sentinels Path to the registered source-glob JSON list.
 * @property {string} [sentinelDir] Directory of runtime sentinel source files.
 * @property {string} [root] Project root for registered source globs.
 */

// Fewer distinct byte values than this in 32 bytes is not a random signature
// (a uniform random one falls below 16 with negligible probability).
const SIGNATURE_MIN_DISTINCT_BYTES = 16;

// Another test worker's bake or rotate holds a freshly staged runtime sentinel open exclusively
// while it sets its permissions (Windows reports EBUSY, EPERM or EACCES). Such a file is retried
// with backoff for up to this long, then the check fails; it is never skipped.
const BUSY_RETRY_MS = 5_000;
const BUSY_CODES = new Set(['EBUSY', 'EPERM', 'EACCES']);
const pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// Sentinel bytes by file identity (resolved path, size, mtime in ns, inode), so an unchanged
// runtime file is not re-read by every check; a changed or new file always is. The bytes are
// cached only when the identity is the same before and after the read. Bounded by entries and bytes.
const SOURCE_CACHE_ENTRIES = 8192;
const SOURCE_CACHE_BYTES = 64 * 1_048_576;
const sourceCache = new Map();
let sourceCacheBytes = 0;
function identity(path) {
  const stat = statSync(path, { bigint: true });
  return `${resolve(path)}\0${stat.size}\0${stat.mtimeNs}\0${stat.ino}`;
}
function cachedRead(path) {
  const before = identity(path);
  const found = sourceCache.get(before);
  if (found) return found;
  const bytes = readFileSync(path);
  if (identity(path) === before && bytes.length <= SOURCE_CACHE_BYTES) {
    while (sourceCache.size >= SOURCE_CACHE_ENTRIES || sourceCacheBytes + bytes.length > SOURCE_CACHE_BYTES) {
      const oldest = sourceCache.keys().next().value;
      sourceCacheBytes -= sourceCache.get(oldest).length;
      sourceCache.delete(oldest);
    }
    sourceCache.set(before, bytes);
    sourceCacheBytes += bytes.length;
  }
  return bytes;
}
function readRuntimeSource(path) {
  const deadline = Date.now() + BUSY_RETRY_MS;
  for (let delay = 25; ; delay = Math.min(delay * 2, 1_000)) {
    try { return cachedRead(path); }
    catch (error) {
      if (!BUSY_CODES.has(error?.code) || Date.now() >= deadline) throw error;
      pause(Math.min(delay, Math.max(1, deadline - Date.now())));
    }
  }
}

/** @param {SentinelOptions} options */
function sentinelSources({ sentinels, sentinelDir, root }) {
  const projectRoot = root ? resolve(root) : resolve(dirname(sentinels), '..');
  // The registered list fails closed: a missing or invalid list, a glob outside the
  // project or a glob that matches no file is an error, never an empty population.
  const globs = JSON.parse(readFileSync(sentinels, 'utf8'));
  if (!Array.isArray(globs) || !globs.every(item => typeof item === 'string')) throw new Error('invalid sentinels list');
  const sourcePaths = globs.flatMap(glob => {
    const prefix = glob.split(/[?*]/, 1)[0];
    const base = resolve(projectRoot, prefix.endsWith('/') ? prefix : dirname(prefix));
    if (base !== projectRoot && !base.startsWith(projectRoot + sep)) throw new Error('sentinel glob outside the project');
    const pattern = globPattern(glob);
    const matched = filesUnder(base).filter(path => pattern.test(relative(projectRoot, path).split(sep).join('/')));
    if (!matched.length) throw new Error('sentinel glob matches no file');
    return matched;
  });
  // Runtime sentinels are written and removed by tests in other workers while this check runs.
  // filesUnder already skips one removed while the directory is listed; one removed between the
  // listing and its read is skipped the same way (it holds no credential any more). A registered
  // source that cannot be read still fails.
  const runtime = new Set(sentinelDir ? filesUnder(sentinelDir) : []);
  sourcePaths.push(...runtime);
  // Read every declared path, including duplicates, so unreadable sources
  // still fail validation. Recognition needs each exact credential only once;
  // source paths remain intact for independent artifact accounting.
  const distinct = new Map();
  for (const path of sourcePaths) {
    let bytes;
    try { bytes = runtime.has(path) ? readRuntimeSource(path) : readFileSync(path); }
    catch (error) {
      if (error?.code === 'ENOENT' && runtime.has(path)) continue;
      throw error;
    }
    if (bytes.length) distinct.set(bytes.toString('hex'), bytes);
    // A v2 macaroon sentinel also registers what is equivalent to it: everything after
    // the constant version byte, and its 32-byte signature (the field after the caveats'
    // end marker: 00 06 20), which with the identifier is the credential.
    if (bytes[0] === 0x02 && bytes.length > 35) {
      const rest = bytes.subarray(1);
      distinct.set(rest.toString('hex'), rest);
      const field = bytes.lastIndexOf(Buffer.from([0x00, 0x06, 0x20]));
      const signature = field >= 0 && field + 35 <= bytes.length ? bytes.subarray(field + 3, field + 35) : null;
      // A real HMAC-SHA256 signature has about 30 distinct byte values; a synthetic
      // placeholder (all zero bytes) would match ordinary data, so it is not registered.
      if (signature && new Set(signature).size >= SIGNATURE_MIN_DISTINCT_BYTES) distinct.set(signature.toString('hex'), signature);
    }
    // An NWC URI sentinel also registers its 32-byte connection secret, so the
    // secret is found in every encoding even when it leaks without the URI.
    for (const match of bytes.toString('latin1').matchAll(/(?:nostr\+walletconnect|nostrwalletconnect):[^\s"'<>]*?[?&]secret=([0-9a-f]{64})(?![0-9a-f])/gi)) {
      const secret = Buffer.from(match[1], 'hex');
      distinct.set(secret.toString('hex'), secret);
    }
  }
  return [...distinct.values()];
}

/** @param {SentinelOptions} options */
export function sentinelRedactor(options) {
  const sources = sentinelSources(options);
  const state = preparedSnapshot(sources).redactor;
  // Cache belongs to this source snapshot only. Bound both retained characters
  // and entry count; oversized strings still receive complete recognition.
  const cache = new Map();
  let retained = 0;
  return text => {
    if (cache.has(text)) return cache.get(text);
    const safe = safePath(text, sources, state);
    const size = text.length + safe.length;
    if (size <= 1_048_576) {
      while (cache.size >= 4096 || retained + size > 1_048_576) {
        const key = cache.keys().next().value;
        retained -= key.length + cache.get(key).length;
        cache.delete(key);
      }
      cache.set(text, safe);
      retained += size;
    }
    return safe;
  };
}

/**
 * @typedef {SentinelOptions & {
 *   paths?: string[], commandOutput?: string, testTmp?: string, evidenceDir?: string
 * }} LeakOptions
 */

/**
 * Inspect command output and candidate files against every distinct sentinel.
 * @param {LeakOptions} options Candidate paths default to an empty array;
 * testTmp supplies declared outputs; candidate artifact links fail closed.
 */
export function findLeaks({ sentinels, sentinelDir, paths = [], commandOutput = '', testTmp, root, evidenceDir }) {
  const projectRoot = root ? resolve(root) : resolve(dirname(sentinels), '..');
  const sources = sentinelSources({ sentinels, sentinelDir, root });
  if (!sources.length) throw new Error('no nonempty sentinel registered');
  const { states, possibleLeak, redactor } = preparedSnapshot(sources);
  const hit = (location, encoding) => ({ path: safePath(location, sources, redactor), encoding });

  // Reject links before reading any artifact, including the output manifest.
  // Source enumeration keeps its separate, existing traversal policy.
  // A named candidate path must exist: a mistyped or removed path is an error, not a pass.
  for (const scanPath of paths) lstatSync(scanPath);
  const candidates = paths.flatMap(scanPath => filesUnder(scanPath, true).map(path => ({
    path, name: lstatSync(scanPath).isDirectory() ? relative(scanPath, path) : basename(path),
  })));
  // A declared output is named by its path, or by `sha256:<hex>` of its resolved path when the
  // path itself holds a credential (a test of path redaction), so the manifest never carries it.
  const declared = new Set();
  const declaredHashes = new Set();
  const pathHash = path => createHash('sha256').update(path, 'utf8').digest('hex');
  if (testTmp && existsSync(join(testTmp, 'declared-out.txt'))) {
    for (const line of readFileSync(join(testTmp, 'declared-out.txt'), 'utf8').split(/\r?\n/)) {
      const entry = line.trim();
      if (/^sha256:[0-9a-f]{64}$/.test(entry)) declaredHashes.add(entry.slice(7));
      else if (entry) declared.add(resolve(testTmp, entry));
    }
  }
  const included = candidates.filter(({ path }) => {
    const absolute = resolve(path);
    const local = relative(projectRoot, absolute).split(sep).join('/');
    const fromEvidence = evidenceDir ? relative(resolve(evidenceDir), absolute) : null;
    const inEvidence = fromEvidence !== null && !isAbsolute(fromEvidence) &&
      fromEvidence !== '..' && !fromEvidence.startsWith(`..${sep}`);
    return inEvidence || (!declared.has(absolute) && !declaredHashes.has(pathHash(absolute)) &&
      !local.startsWith('test/vectors/') && !local.startsWith('test/scan-fixtures/'));
  });
  const haystacks = [['command output', Buffer.from(commandOutput), ''],
    ...included.map(({ path, name }) => [path, readFileSync(path), name])];
  for (const [location, data, name] of haystacks) {
    // Artifact decoding is independent of the credential population. Prepare
    // it once, while still comparing every exact registered credential.
    const input = preparedData(data);
    const nameData = name ? Buffer.from(name) : null;
    const nameInput = nameData ? preparedData(nameData) : null;
    if (!possibleLeak(input) && (!nameInput || !possibleLeak(nameInput))) continue;
    const lowerName = name.toLowerCase();
    for (const state of states) {
      const { source } = state;
      for (const { encoding, value, lower, bytes } of state.variants) {
        if (name &&
            (encoding.startsWith('hex-') ? lowerName.includes(lower) : name.includes(value))) {
          return hit(location, encoding);
        }
        if (data.includes(bytes)) return hit(location, encoding);
      }
      const alternateName = nameData && alternateEncoding(nameData, source, state, nameInput);
      if (alternateName) return hit(location, alternateName);
      if (data.includes(source)) return hit(location, 'raw-bytes');
      const alternate = alternateEncoding(data, source, state, input);
      if (alternate) return hit(location, alternate);
    }
  }
  return null;
}

function main(args) {
  if (args[0] !== '--sentinels' || !args[1]) return 2;
  const sentinels = resolve(args[1]);
  let index = 2;
  let sentinelDir;
  if (args[index] === '--sentinel-dir') {
    if (!args[index + 1]) return 2;
    sentinelDir = resolve(args[index + 1]); index += 2;
  }
  if (index >= args.length || args.slice(index).some(arg => arg.startsWith('--'))) return 2;
  try {
    const hit = findLeaks({ sentinels, sentinelDir, paths: args.slice(index).map(path => resolve(path)),
      testTmp: process.env.MACWARDEN_TEST_TMP });
    if (hit) { process.stderr.write(`${hit.path}: ${hit.encoding}\n`); return 1; }
    return 0;
  } catch {
    process.stderr.write('leak-check failed\n');
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
