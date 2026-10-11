import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, lstatSync, statSync, existsSync } from 'node:fs';
import { resolve, relative, dirname, basename, join, sep, isAbsolute } from 'node:path';
import { availableParallelism, freemem } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

// Character classes of groupedBase64Runs by UTF-16 code unit, built once from the
// very regular expressions it used per character (identical answers, no per-character
// regex call). Bit 1: base64 digit; 2: '_'; 4: '-'; 8: an 'other' shape separator.
const CHARACTER_CLASS = (() => {
  const table = new Uint8Array(65536);
  for (let code = 0; code < 65536; code++) {
    const character = String.fromCharCode(code);
    table[code] = (/^[A-Za-z0-9+/]$/.test(character) ? 1 : 0) | (character === '_' ? 2 : 0) |
      (character === '-' ? 4 : 0) | (!/^[A-Za-z0-9+/_=\s\\-]$/.test(character) ? 8 : 0);
  }
  return table;
})();

// Same leftmost-greedy matches as /W+(?:SW+)+={0,2}/g for the three grouped base64
// shapes, in linear time (the regular expressions backtrack quadratically over long
// unseparated runs). Mirrors src/grouped-runs.ts; test/grouped-runs.test.ts checks both.
export function groupedBase64Runs(text, shape) {
  const wordMask = shape === 'dash' ? 1 | 2 : shape === 'underscore' ? 1 : 1 | 2 | 4;
  const separatorMask = shape === 'dash' ? 4 : shape === 'underscore' ? 2 : 8;
  const word = at => (CHARACTER_CLASS[text.charCodeAt(at)] & wordMask) !== 0;
  const separator = at => (CHARACTER_CLASS[text.charCodeAt(at)] & separatorMask) !== 0;
  const runs = [];
  let at = 0;
  while (at < text.length) {
    if (!word(at)) { at++; continue; }
    const start = at;
    while (at < text.length && word(at)) at++;
    let end = at, groups = 1;
    while (end + 1 < text.length && separator(end) && word(end + 1)) {
      end++;
      while (end < text.length && word(end)) end++;
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

// Exact multi-literal byte search, linear in the haystack (the former literal
// alternation regexes cost O(bytes x literals) per view). A literal occurrence spans
// `stride` consecutive window offsets of the literal (each an 8-byte window inside
// it) only if one of them starts at a haystack offset that is a multiple of the
// stride. Those windows of each literal are indexed in a hash table; the haystack is
// probed every `stride` bytes and every candidate is verified byte for byte at its
// implied start, so the answer is exactly "some literal occurs". Literals shorter
// than a window use native indexOf.
const WINDOW = 8;
// One probe every 8 bytes. A wider stride for some literals would need a second
// pass, and the UTF-8 forms of binary credentials (mostly U+FFFD) need a narrow one.
const STRIDE = 8;
const word = (bytes, at) => bytes[at] | bytes[at + 1] << 8 | bytes[at + 2] << 16 | bytes[at + 3] << 24;

// The stride (8, or length - 7 for a shorter literal, so the windows fit) and the
// first of that many consecutive windows whose least varied window has the most
// distinct byte values, preferring the tail. Every one of them is probed for, and a
// window with few distinct values (a zero run, the U+FFFD runs of the UTF-8 form of
// a binary credential, a prefix all macaroons share) is common in artifacts.
function literalWindows(value) {
  const distinct = [];
  // Distinct byte values of each window, by sliding byte counts.
  const counts = new Uint8Array(256);
  let values = 0;
  for (let at = 0; at < value.length; at++) {
    if (counts[value[at]]++ === 0) values++;
    if (at >= WINDOW && --counts[value[at - WINDOW]] === 0) values--;
    if (at >= WINDOW - 1) distinct.push(values);
  }
  const run = stride => {
    let best = 0, bestScore = -1;
    for (let first = 0; first + stride <= distinct.length; first++) {
      let score = WINDOW;
      for (let at = first; at < first + stride; at++) score = Math.min(score, distinct[at]);
      if (score >= bestScore) { best = first; bestScore = score; }
    }
    return { first: best };
  };
  const stride = Math.min(STRIDE, distinct.length);
  return { stride, first: run(stride).first };
}

function windowIndex(entries, stride) {
  const count = entries.length * stride;
  let bits = 10;
  while ((1 << bits) < count * 2) bits++;
  const shift = 32 - bits;
  const slot = (low, high) => (Math.imul(low, 0x9e3779b1) ^ Math.imul(high ^ high >>> 15, 0x85ebca77)) >>> shift;
  const heads = new Int32Array(1 << bits).fill(-1);
  const keyLow = new Int32Array(count), keyHigh = new Int32Array(count), next = new Int32Array(count);
  const literal = new Int32Array(count), offset = new Int32Array(count);
  const literals = entries.map(({ value }) => value);
  let entry = 0;
  entries.forEach(({ value, first }, index) => {
    for (let at = first; at < first + stride; at++, entry++) {
      keyLow[entry] = word(value, at); keyHigh[entry] = word(value, at + 4);
      literal[entry] = index; offset[entry] = at;
      const head = slot(keyLow[entry], keyHigh[entry]);
      next[entry] = heads[head]; heads[head] = entry;
    }
  });
  return bytes => {
    const length = bytes.length;
    for (let at = 0; at + WINDOW <= length; at += stride) {
      const low = word(bytes, at), high = word(bytes, at + 4);
      for (let candidate = heads[slot(low, high)]; candidate !== -1; candidate = next[candidate]) {
        if (keyLow[candidate] !== low || keyHigh[candidate] !== high) continue;
        const value = literals[literal[candidate]];
        const start = at - offset[candidate];
        if (start < 0 || start + value.length > length) continue;
        let index = 0;
        while (index < value.length && bytes[start + index] === value[index]) index++;
        if (index === value.length) return true;
      }
    }
    return false;
  };
}

function literalMatcher(values) {
  const unique = new Map();
  for (const value of values) if (value.length) unique.set(value.toString('latin1'), value);
  const short = [];
  const classes = new Map();
  for (const value of unique.values()) {
    if (value.length < WINDOW) { short.push(value); continue; }
    const { stride, first } = literalWindows(value);
    if (!classes.has(stride)) classes.set(stride, []);
    classes.get(stride).push({ value, first });
  }
  const searches = [...classes].map(([stride, entries]) => windowIndex(entries, stride));
  return bytes => short.some(value => bytes.includes(value)) || searches.some(search => search(bytes));
}

// The same literal sets and views as before: raw credentials in byte views
// (artifact bytes, decoded hex, decimal and base64 streams), every literal
// encoding in every text view. A hit may cross a parser boundary; the detailed
// checks in findLeaks still enforce all boundaries and choose the encoding.
// Filters by exact source population (complete bytes in order, as the snapshot
// cache keys them), so a population over the snapshot cache bound, and the redactor
// of the same population, do not rebuild the index on every call.
const filters = new Map();
function cachedFilter(states) {
  const key = states.map(state => state.hex).join(':');
  const found = filters.get(key);
  if (found) return found;
  const filter = preparedFilter(states);
  while (filters.size >= 4) filters.delete(filters.keys().next().value);
  filters.set(key, filter);
  return filter;
}

function preparedFilter(states) {
  const rawLiterals = states.map(state => state.source);
  const encodedLiterals = states.flatMap(state => [
    ...state.variants.map(variant => variant.bytes), state.utf16le, state.utf16be,
    Buffer.from(state.percentBytes), Buffer.from(state.escapedBytes),
  ]);
  const raw = literalMatcher(rawLiterals);
  const encoded = literalMatcher(encodedLiterals);
  const both = literalMatcher([...rawLiterals, ...encodedLiterals]);
  const possibleLeak = input => {
    if (both(input.data)) return true;
    if ([...input.recovered, input.lower, input.compact, input.compactLower,
      input.percent, input.percentLower, ...input.splitViews].some(encoded)) return true;
    if (input.hexStreams().some(stream => both(stream.bytes)) ||
        input.decimalStream().some(stream => raw(stream.bytes))) return true;
    return input.base64Runs.some(both);
  };
  return { possibleLeak, encoded };
}

function safePath(path, sources, state = preparedRedactor(sources)) {
  if (path === 'command output') return path;
  // A string none of whose views holds any registered literal is returned as is:
  // every redaction value is one of those literals (hex ones case-insensitively,
  // hence the lowercased view), and every alternateEncoding branch searches one
  // of those views for one of them, so the full pass would change nothing.
  state.filter ??= cachedFilter(state.sources);
  const name = basename(path);
  if (!state.filter.possibleLeak(preparedData(Buffer.from(path))) &&
      !(name !== path && state.filter.possibleLeak(preparedData(Buffer.from(name)))) &&
      !state.filter.encoded(Buffer.from(path.toLowerCase()))) return path;
  return fullSafePath(path, state);
}

// Every redaction and every alternate encoding of every source, unconditionally.
function fullSafePath(path, state) {
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
  const filter = sources.length ? cachedFilter(states) : null;
  const state = { states, possibleLeak: filter?.possibleLeak ?? null, encodedLeak: filter?.encoded ?? null,
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

// Everything findLeaks decides before reading an artifact: the sentinel snapshot,
// link rejection, the candidate list and the declared-output exclusions.
function leakPlan({ sentinels, sentinelDir, paths = [], commandOutput = '', testTmp, root, evidenceDir }) {
  const projectRoot = root ? resolve(root) : resolve(dirname(sentinels), '..');
  const sources = sentinelSources({ sentinels, sentinelDir, root });
  if (!sources.length) throw new Error('no nonempty sentinel registered');

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
  return { sources, commandOutput, included };
}

// The encoding of the first registered credential found in one artifact (or its
// name), or null. Credentials are tried in snapshot order, as they always were.
function scanArtifact(snapshot, data, name) {
  const { states, possibleLeak, encodedLeak } = snapshot;
  // Artifact decoding is independent of the credential population. Prepare
  // it once, while still comparing every exact registered credential.
  const input = preparedData(data);
  const nameData = name ? Buffer.from(name) : null;
  const nameInput = nameData ? preparedData(nameData) : null;
  // The lowercased name covers the case-insensitive hex comparison of names below.
  if (!possibleLeak(input) && (!nameInput || (!possibleLeak(nameInput) &&
      !encodedLeak(Buffer.from(name.toLowerCase()))))) return null;
  const lowerName = name.toLowerCase();
  for (const state of states) {
    const { source } = state;
    for (const { encoding, value, lower, bytes } of state.variants) {
      if (name &&
          (encoding.startsWith('hex-') ? lowerName.includes(lower) : name.includes(value))) {
        return encoding;
      }
      if (data.includes(bytes)) return encoding;
    }
    const alternateName = nameData && alternateEncoding(nameData, source, state, nameInput);
    if (alternateName) return alternateName;
    if (data.includes(source)) return 'raw-bytes';
    const alternate = alternateEncoding(data, source, state, input);
    if (alternate) return alternate;
  }
  return null;
}

/**
 * Inspect command output and candidate files against every distinct sentinel.
 * @param {LeakOptions} options Candidate paths default to an empty array;
 * testTmp supplies declared outputs; candidate artifact links fail closed.
 */
export function findLeaks(options) {
  const { sources, commandOutput, included } = leakPlan(options);
  const snapshot = preparedSnapshot(sources);
  // Every artifact is read before any is scanned: an unreadable one fails the check
  // even when another holds a credential.
  const haystacks = [['command output', Buffer.from(commandOutput), ''],
    ...included.map(({ path, name }) => [path, readFileSync(path), name])];
  for (const [location, data, name] of haystacks) {
    const encoding = scanArtifact(snapshot, data, name);
    if (encoding) return { path: safePath(location, sources, snapshot.redactor), encoding };
  }
  return null;
}

// Each worker builds its own matchers for every owner's sentinels: about 0.55 GB at the end of a
// full validation (20 workers held 11.3 GB on 2026-10-11, and the host ran short of memory).
const WORKER_BYTES = 640 * 1024 * 1024;

/**
 * Worker count for leakScans: every processor but two, at most 20, and no more than half of the
 * free memory holds at WORKER_BYTES each; at least 1.
 */
export function leakScanWorkers(processors = availableParallelism(), free = freemem()) {
  return Math.max(1, Math.min(processors - 2, 20, Math.floor(free / 2 / WORKER_BYTES)));
}

/**
 * findLeaks for several independent option sets at once, on one pool of worker threads.
 * Each result is what findLeaks would return or throw for that set: the hit in its first
 * artifact (command output, then candidates in traversal order), unless an artifact is
 * unreadable, whose error then wins as in findLeaks (the first such by that order). Any
 * worker failure fails every set (fail closed).
 * @param {LeakOptions[]} optionSets
 * @returns {Promise<Array<{ hit: { path: string, encoding: string } | null } | { error: Error }>>}
 */
export async function leakScans(optionSets, workers = leakScanWorkers()) {
  const plans = optionSets.map(options => {
    try { return leakPlan(options); }
    catch (error) { return { error }; }
  });
  const owners = [];
  const tasks = [];
  plans.forEach((plan, owner) => {
    if (plan.error) return;
    owners.push({ owner, sources: plan.sources, commandOutput: plan.commandOutput });
    tasks.push({ owner, index: 0, path: null, name: '', size: Buffer.byteLength(plan.commandOutput) });
    plan.included.forEach(({ path, name }, offset) => {
      let size = 0;
      try { size = lstatSync(path).size; } catch { /* the worker's read reports it */ }
      tasks.push({ owner, index: offset + 1, path, name, size });
    });
  });
  // Largest first, so one big file does not start last and hold up the pool.
  tasks.sort((a, b) => b.size - a.size);
  const outcomes = plans.map(() => ({ hit: null, error: null }));
  if (tasks.length) {
    // shared[0] is the task cursor; shared[1 + owner] the lowest artifact index with
    // a hit so far: later artifacts of that owner are still read (an unreadable one
    // still fails) but no longer scanned.
    const shared = new Int32Array(new SharedArrayBuffer(4 * (1 + plans.length)));
    shared.fill(0x7fffffff, 1);
    const workerData = { owners, tasks: tasks.map(({ owner, index, path, name }) => ({ owner, index, path, name })), shared };
    const count = Math.max(1, Math.min(workers, tasks.length));
    const runs = Array.from({ length: count }, () => new Promise((resolveRun, rejectRun) => {
      const worker = new Worker(new URL('./leak-scan-worker.mjs', import.meta.url), { workerData });
      let done = false;
      worker.on('message', message => {
        const outcome = outcomes[message.owner];
        if (message.type === 'hit' && (!outcome.hit || message.index < outcome.hit.index)) outcome.hit = message;
        else if (message.type === 'error' && (!outcome.error || message.index < outcome.error.index)) outcome.error = message;
        else if (message.type === 'done') done = true;
      });
      worker.on('error', rejectRun);
      worker.on('exit', code => done && code === 0 ? resolveRun() : rejectRun(new Error(`leak scan worker exited (${code})`)));
    }));
    const failed = (await Promise.allSettled(runs)).find(run => run.status === 'rejected');
    if (failed) {
      const error = failed.reason instanceof Error ? failed.reason : new Error(String(failed.reason));
      return plans.map(plan => ({ error: plan.error ?? error }));
    }
  }
  return plans.map((plan, owner) => {
    if (plan.error) return { error: plan.error };
    const { hit, error } = outcomes[owner];
    if (error) return { error: Object.assign(new Error(error.message), { code: error.code }) };
    if (!hit) return { hit: null };
    const location = hit.index === 0 ? 'command output' : plan.included[hit.index - 1].path;
    const { redactor } = preparedSnapshot(plan.sources);
    return { hit: { path: safePath(location, plan.sources, redactor), encoding: hit.encoding } };
  });
}

/** The task loop of one leakScans worker thread (scripts/leak-scan-worker.mjs). */
export function leakScanWorker({ owners, tasks, shared }, post) {
  const snapshots = new Map(owners.map(({ owner, sources, commandOutput }) =>
    [owner, { snapshot: preparedSnapshot(sources.map(source => Buffer.from(source))), commandOutput }]));
  for (let next; (next = Atomics.add(shared, 0, 1)) < tasks.length;) {
    const { owner, index, path, name } = tasks[next];
    const { snapshot, commandOutput } = snapshots.get(owner);
    let data;
    try { data = path === null ? Buffer.from(commandOutput) : readFileSync(path); }
    catch (error) {
      post({ type: 'error', owner, index, message: error instanceof Error ? error.message : String(error), code: error?.code });
      continue;
    }
    if (index > Atomics.load(shared, 1 + owner)) continue;
    const encoding = scanArtifact(snapshot, data, name);
    if (!encoding) continue;
    for (let best = Atomics.load(shared, 1 + owner); index < best;) {
      const seen = Atomics.compareExchange(shared, 1 + owner, best, index);
      if (seen === best) break;
      best = seen;
    }
    post({ type: 'hit', owner, index, encoding });
  }
  post({ type: 'done' });
}

// For test/harness/leak-prefilter-differential.test.ts, which checks the prefilter
// and the redactor fast path against their reference definitions.
export const internals = Object.freeze({ variants, preparedCredential, preparedData, preparedFilter,
  preparedRedactor, safePath, fullSafePath });

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
