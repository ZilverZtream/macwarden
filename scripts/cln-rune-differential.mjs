// Differential comparison of macwarden's rune decoding and assessment with a regtest Core
// Lightning v26.06.8 node (test/fixture/cln-fixture.mjs). Shared by the CI-sized oracle test
// (test/cln-oracle/rune-differential.test.ts) and the full campaign (scripts/cln-rune-campaign.mjs).
//
//   1. Created runes: random restriction sets (every condition, escapes of & | \, unicode, long
//      values, many alternatives) go through `createrune`; macwarden's unique ID, version and
//      restrictions must equal native `decode` and the restrictions asked for.
//   2. Mutated texts: each created rune is mutated (scripts/rune-fuzz-core.mjs); macwarden must
//      accept exactly the texts checkrune's rune parser accepts (param_rune: "should be base64
//      string" is a refusal), except texts beyond macwarden's bounds, counted apart; where native
//      decode shows a rune, the facts must agree.
//   3. checkrune pairs: runes without rate or per restrictions, each checked with random requests
//      (method, params, peer). Whatever checkrune accepts, macwarden must report as possible;
//      requests macwarden allows and checkrune refuses are counted as over-reporting. The
//      in-process model (concreteCheck) is compared with checkrune too.
//
// Rune texts never leave this module in a report: failures name the case by seed and index,
// and show the restrictions that were asked for (test data on a disposable node).
import { caseSeed, checkCondition, concreteCheck, describe, mutate, prng } from './rune-fuzz-core.mjs';

const CONDITIONS = '!=/^$~<>{}#';
const SAFE = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
const VALUE_CHARACTERS = [...SAFE, '&', '|', '\\', '&', '|', '\\', '-', '=', ' ', '"', "'", '/', '!', '#', '{', '}', '<', '>', '^', '$', '~',
  'é', '☕', '日', '\u{1F600}', 'Ω'];
const FIELD_UNICODE = ['é', 'ß', '日本', 'Ω'];
const KNOWN = ['method', 'method', 'method', 'time', 'id', 'pnum', 'pnameamount_msat', 'pnamelabel', 'pnameamountmsat', 'parr0', 'parr1',
  'pinvbolt11_amount', 'pinvbolt11_description', 'pinvbolt11_node', 'pinvbolt11_payee', 'colour', 'pname'];
const NUMBERS = ['0', '1', '-1', '5', ' 7', '+3', '1000', '50000', '9223372036854775807', '9223372036854775808', '-9223372036854775808', '1e3',
  '1.5', '00012', '\t4'];
const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

function latin1(text) { return Buffer.from(text, 'utf8').toString('latin1'); }
function utf8(bytes) { return Buffer.from(bytes, 'latin1').toString('utf8'); }

function value(r, pool) {
  if (pool.length && r.chance(0.45)) return r.pick(pool);
  const length = r.chance(0.04) ? r.int(300, 1800) : r.int(0, 20);
  let text = '';
  while ([...text].length < length) text += r.pick(VALUE_CHARACTERS);
  return text;
}

function field(r, { rate }) {
  const known = rate ? [...KNOWN, 'rate', 'per'] : KNOWN;
  if (r.chance(0.75)) return r.pick(known);
  let name = '';
  for (let i = r.int(1, 10); i > 0; i--) name += r.chance(0.9) ? r.pick(SAFE) : r.chance(0.5) ? ' ' : r.pick(FIELD_UNICODE);
  return name;
}

/** Random restrictions as createrune takes them: arrays of "field<condition>value" strings (UTF-8). */
// Alternatives that many requests pass, so that permissive runes give checkrune something to accept.
const LIKELY = ['pnamex!', 'parr9!', 'method^list', 'method^get', 'method/pay', 'pnum<5', 'note#anything', 'time>1600000000', 'id!',
  'method~in', 'method}a', 'method{z', 'pnamelabel/x'];

export function randomRestrictions(r, { methods, now, rate = false, large = false, permissive = false }) {
  const timePool = [String(now - 1_000_000n), String(now + 1_000_000n), String(now - 50_000_000n), '1600000000', '4000000000'];
  const pool = [...methods.slice(0, 60), ...NUMBERS, ...timePool, G, 'coffee', 'tea', ''];
  const count = large ? r.int(250, 280) : permissive ? r.int(1, 3) : r.chance(0.08) ? r.int(10, 60) : r.int(1, 5);
  const restrictions = [];
  for (let i = 0; i < count; i++) {
    const alternatives = large ? r.int(1, 5) : r.chance(0.08) ? r.int(8, 40) : r.int(1, 4);
    const restriction = [];
    for (let j = 0; j < alternatives; j++) {
      const name = field(r, { rate });
      let condition = r.pick(CONDITIONS);
      let text = value(r, name === 'method' ? methods : pool);
      if ((name === 'rate' || name === 'per') && r.chance(0.7)) { condition = '='; text = r.pick(['1', '5', '60', '10sec', '2min', '0', 'x']); }
      restriction.push(`${name}${condition}${text}`);
    }
    if (permissive && r.chance(0.6)) restriction.splice(r.int(0, restriction.length), 0, r.pick(LIKELY));
    restrictions.push(restriction);
  }
  return restrictions;
}

/** The facts the restrictions should decode to: alternatives as latin1 byte strings. */
function expected(restrictions) {
  return restrictions.map(restriction => restriction.map(text => {
    const bytes = latin1(text);
    let end = 0;
    while (end < bytes.length && !(/[!-/:-@[-`{-~]/.test(bytes[end]) && bytes[end] !== '_')) end++;
    return { field: bytes.slice(0, end), condition: bytes[end], value: bytes.slice(end + 1) };
  }));
}

/** Our alternatives in native decode's form: field, condition and unescaped value, as UTF-8. */
function shown(restrictions) {
  return restrictions.map(restriction => restriction.map(alt => utf8(`${alt.field}${alt.condition}${alt.value}`)));
}

/** A unique ID or version (latin1 byte string or null) as native decode prints it. */
function text8(bytes) { return bytes === null ? null : utf8(bytes); }

/** Text whose JSON string token is the text itself: quotes, backslashes and control characters become 'x'. */
const BACKSLASH = String.fromCharCode(92);
function plain(text) { return [...text].map(character => character < ' ' || character === '"' || character === BACKSLASH ? 'x' : character).join(''); }

function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

/** JSON text of a model parameter value, and the model value Core Lightning sees for it. */
function parameter(r, pool) {
  const roll = r.next();
  if (roll < 0.35) {
    const text = r.pick(NUMBERS.filter(item => /^-?[0-9]+(\.[0-9]+)?(e[0-9]+)?$/.test(item)).concat(['0', '42', '99999', '-0', '18446744073709551617']));
    // json_to_s64: an integer token within s64 is an integer; anything else is compared as its token text.
    const integer = /^-?[0-9]+$/.test(text) && BigInt(text) >= -(2n ** 63n) && BigInt(text) < 2n ** 63n;
    return { json: text, model: integer ? { int: BigInt(text) } : { str: text } };
  }
  if (roll < 0.42) return { json: r.pick(['true', 'false', 'null']), model: null };
  if (roll < 0.47) return { json: '{"a":1}', model: { str: '{"a":1}' } };
  let text = pool.length && r.chance(0.7) ? r.pick(pool) : value(r, []);
  if (r.chance(0.2)) text += 'x';
  text = plain(text);
  return { json: JSON.stringify(text), model: { str: latin1(text) } };
}

/**
 * A random request for a rune's restrictions (latin1 facts), as checkrune params text plus the
 * model request concreteCheck takes. `invoices` are real bolt11 invoices of the node.
 */
function randomRequest(r, restrictions, { methods, invoices, nodeId }) {
  const alternatives = restrictions.flat();
  const named = alternatives.filter(alt => alt.field === 'method').map(alt => utf8(alt.value));
  let method = r.chance(0.45) && named.length ? r.pick(named) : r.chance(0.85) ? r.pick(methods) : value(r, []);
  if (r.chance(0.1)) method += r.pick(['x', 's', '-']);
  method = plain(method);
  const valuePool = alternatives.map(alt => utf8(alt.value));
  let paramsJson = null;
  let params = null;
  const modelInvoices = new Map();
  if (r.chance(0.85)) {
    if (r.chance(0.75)) {
      const keys = new Set();
      for (const alt of alternatives) {
        if (alt.field.startsWith('pname') && r.chance(0.7)) keys.add(utf8(alt.field.slice(5)));
        if (alt.field.startsWith('pinv') && r.chance(0.8)) keys.add(utf8(alt.field.slice(4).replace(/_(amount|description|node)$/, '')));
      }
      if (r.chance(0.3)) keys.add(r.pick(['amount-msat', 'label', 'x_y', 'amount_msat']));
      const entries = [];
      const members = [];
      for (const key of [...keys].filter(item => plain(item) === item)) {
        let item = parameter(r, valuePool);
        if (r.chance(0.6)) {
          const invoice = r.pick(invoices);
          item = { json: JSON.stringify(invoice.bolt11), model: { str: invoice.bolt11 } };
          modelInvoices.set(latin1(key), invoice.facts);
        } else modelInvoices.set(latin1(key), 'invalid');
        members.push(`${JSON.stringify(key)}:${item.json}`);
        if (item.model !== null) entries.push([latin1(key), item.model]);
        else entries.push([latin1(key), { str: JSON.parse(item.json) === null ? 'null' : String(JSON.parse(item.json)) }]);
      }
      paramsJson = `{${members.join(',')}}`;
      params = { object: entries };
    } else {
      const items = Array.from({ length: r.int(0, 4) }, () => parameter(r, valuePool));
      paramsJson = `[${items.map(item => item.json).join(',')}]`;
      params = { array: items.map(item => item.model ?? { str: item.json }) };
    }
  }
  const peer = r.chance(0.35) ? null : r.chance(0.5) ? nodeId : G;
  const fields = [`"rune":RUNE`, `"method":${JSON.stringify(method)}`];
  if (paramsJson !== null) fields.push(`"params":${paramsJson}`);
  if (peer !== null) fields.push(`"nodeid":"${peer}"`);
  return { json: `{${fields.join(',')}}`, model: { method: latin1(method), peer, params, rateOk: true, invoices: modelInvoices } };
}

/**
 * Runs the comparison. `rpc` is a fixture session; `api` holds macwarden's decodeRuneText,
 * assessRune, methodMayPass, CLN_METHODS and RUNE_* limits. Returns counts and failures.
 */
/**
 * @param {{ call(method: string, params?: object | string): Promise<{ result?: any, error?: any }> }} rpc
 * @param {Record<string, any>} api
 * @param {{ seed: number, runes: number, pairsPerRune?: number, mutationsPerRune?: number,
 *   onProgress?: (done: number, report: any) => void }} options
 */
export async function runDifferential(rpc, api, { seed, runes, pairsPerRune = 2, mutationsPerRune = 2, onProgress }) {
  const methods = Object.keys(api.CLN_METHODS);
  const info = await rpc.call('getinfo');
  const nodeId = info.result.id;
  const invoices = [];
  for (const [amount, description] of [[1000, 'coffee'], [50000, 'tea ☕'], ['any', 'donation']]) {
    const made = await rpc.call('invoice', { amount_msat: amount, label: `fuzz-${seed}-${description}-${Date.now()}-${invoices.length}`, description });
    if (!made.result) throw new Error(`invoice failed: ${JSON.stringify(made.error)}`);
    invoices.push({ bolt11: made.result.bolt11, facts: { amount: amount === 'any' ? undefined : BigInt(amount), description: latin1(description), node: nodeId } });
  }
  const report = {
    seed, runes: 0, created: 0, createRefused: 0, decodeCompared: 0, beyondBounds: 0,
    mutations: 0, mutationsAgree: 0, mutationsBeyondBounds: 0, mutationAccepted: 0, mutationRefused: 0, nativeDecodeCompared: 0,
    pairs: 0, accepted: 0, refused: 0, otherErrors: 0, overReported: 0, overReportedByField: /** @type {Record<string, number>} */ ({}),
    modelAgrees: 0, modelDisagrees: 0, modelDisagreements: /** @type {object[]} */ ([]), failures: /** @type {{ seed: number, index: number, kind: string, message: string }[]} */ ([]),
  };
  const fail = (index, kind, message) => { if (report.failures.length < 50) report.failures.push({ seed, index, kind, message }); };
  const now = BigInt(Math.floor(Date.now() / 1000));
  for (let index = 0; index < runes; index++) {
    const r = prng(caseSeed(seed, index));
    report.runes++;
    // Every fourth rune may hold rate and per restrictions; those are never checked with checkrune.
    const rate = index % 4 === 3;
    const asked = randomRestrictions(r, { methods, now, rate, large: r.chance(0.02), permissive: index % 2 === 0 });
    const created = await rpc.call('createrune', { restrictions: asked });
    if (!created.result) { report.createRefused++; continue; }
    report.created++;
    const text = created.result.rune;
    const native = (await rpc.call('decode', { string: text })).result;
    const ours = api.decodeRuneText(text);
    const want = expected(asked);
    const restrictionCount = asked.length + 1;
    const alternativeCount = asked.reduce((sum, item) => sum + item.length, 1);
    const beyond = text.length > api.RUNE_TEXT_LIMIT || restrictionCount > api.RUNE_RESTRICTION_LIMIT || alternativeCount > api.RUNE_ALTERNATIVE_LIMIT;
    if (beyond) {
      report.beyondBounds++;
      if (ours.ok || ours.reason !== 'exceeds-bounds') fail(index, 'created', `beyond bounds but ${ours.ok ? 'decoded' : ours.reason}`);
    } else if (!ours.ok) fail(index, 'created', `refused a created rune (${ours.reason}): ${describe(asked)}`);
    else {
      report.decodeCompared++;
      if (native?.type !== 'rune' || native.valid === false) fail(index, 'created', `native decode did not show the rune: ${describe(asked)}`);
      else {
        if (text8(ours.facts.uniqueId) !== (native.unique_id ?? null)) fail(index, 'created', 'unique ID differs from native decode');
        if (text8(ours.facts.version) !== (native.version ?? null)) fail(index, 'created', 'version differs from native decode');
        if (!same(shown(ours.facts.restrictions), (native.restrictions ?? []).map(item => item.alternatives)))
          fail(index, 'created', `restrictions differ from native decode: ${describe(asked)}`);
      }
      if (!same(ours.facts.restrictions, want)) fail(index, 'created', `restrictions differ from those asked for: ${describe(asked)}`);
      if (ours.facts.nonCanonical) fail(index, 'created', 'a rune Core Lightning wrote is reported non-canonical');
    }

    // Mutated texts: acceptance by checkrune's parser.
    const bytes = Buffer.from(text.replace(/=+$/, ''), 'base64url');
    for (let m = 0; m < mutationsPerRune; m++) {
      const mutated = mutate(r, text, bytes);
      report.mutations++;
      const checked = await rpc.call('checkrune', { rune: mutated });
      const parserRefused = /should be base64 string/.test(checked.error?.message ?? '');
      const mine = api.decodeRuneText(mutated);
      if (!mine.ok && mine.reason === 'exceeds-bounds') { report.mutationsBeyondBounds++; continue; }
      if (mine.ok === !parserRefused) report.mutationsAgree++;
      else fail(index, 'mutation', `macwarden ${mine.ok ? 'decodes' : `refuses (${mine.reason})`}, checkrune's parser ${parserRefused ? 'refuses' : 'accepts'} (mutation ${m})`);
      if (mine.ok) report.mutationAccepted++; else report.mutationRefused++;
      if (mine.ok) {
        const decoded = (await rpc.call('decode', { string: mutated })).result;
        if (decoded?.type === 'rune' && decoded.valid !== false) {
          report.nativeDecodeCompared++;
          if (text8(mine.facts.uniqueId) !== (decoded.unique_id ?? null) || text8(mine.facts.version) !== (decoded.version ?? null)
            || !same(shown(mine.facts.restrictions), (decoded.restrictions ?? []).map(item => item.alternatives)))
            fail(index, 'mutation', `facts differ from native decode (mutation ${m}): ours ${describe([mine.facts.uniqueId, mine.facts.version,
              shown(mine.facts.restrictions)])}, native ${describe([decoded.unique_id, decoded.version, (decoded.restrictions ?? []).map(item => item.alternatives)])}`);
        }
      }
    }

    // checkrune pairs.
    if (rate || beyond || !ours.ok) continue;
    const facts = ours.facts;
    const assessment = api.assessRune(facts, now);
    for (let k = 0; k < pairsPerRune; k++) {
      const request = randomRequest(r, facts.restrictions, { methods, invoices, nodeId });
      const result = await rpc.call('checkrune', request.json.replace('RUNE', JSON.stringify(text)));
      report.pairs++;
      const accepted = result.result?.valid === true;
      if (!accepted && !/^Not permitted/.test(result.error?.message ?? '')) { report.otherErrors++; fail(index, 'checkrune', `unexpected checkrune answer ${describe(result.error)}`); continue; }
      if (accepted) report.accepted++; else report.refused++;
      const model = { ...request.model, time: BigInt(Math.floor(Date.now() / 1000)) };
      const predicted = concreteCheck(facts.restrictions, model);
      if (predicted === accepted) report.modelAgrees++;
      else {
        report.modelDisagrees++;
        if (report.modelDisagreements.length < 10) report.modelDisagreements.push({ index, accepted, restrictions: describe(asked), request: describe(model) });
      }
      const method = model.method;
      const inTable = Object.hasOwn(api.CLN_METHODS, method);
      const mayPass = inTable ? api.methodMayPass(facts, method)
        : assessment.methods === 'broad' || assessment.unreviewedMethods.includes(method);
      if (accepted && !mayPass) fail(index, 'soundness', `checkrune accepted ${JSON.stringify(utf8(method))}, macwarden reports it impossible: ${describe(asked)}`);
      if (accepted && assessment.methods === 'none') fail(index, 'soundness', `checkrune accepted a rune macwarden reports as matching no method: ${describe(asked)}`);
      if (accepted && assessment.expiry.status === 'deadline-passed') fail(index, 'soundness', 'checkrune accepted a rune macwarden reports expired');
      if (!accepted && mayPass) {
        report.overReported++;
        // The first restriction that refused the request, by the kind of field that refused it.
        const blocking = facts.restrictions.find(restriction => !restriction.some(alt => checkCondition(alt, model)));
        const key = blocking ? [...new Set(blocking.map(alt => /^(method|time|id|pnum)$/.test(alt.field) ? alt.field
          : alt.field.startsWith('pinv') ? 'pinv' : alt.field.startsWith('pname') || alt.field.startsWith('parr') ? 'parameter' : 'other'))].sort().join('+')
          : 'unexplained';
        report.overReportedByField[key] = (report.overReportedByField[key] ?? 0) + 1;
      }
    }
    if (onProgress && (index + 1) % 250 === 0) onProgress(index + 1, report);
  }
  return report;
}

