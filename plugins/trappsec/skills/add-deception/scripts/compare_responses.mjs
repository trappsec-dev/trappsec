#!/usr/bin/env node
// Compare a decoy's response with a real endpoint's, the way a careful tester would.
//
//   node compare_responses.mjs --real http://localhost:3000/api/v2/reports/1 \
//                              --decoy http://localhost:3000/api/v2/reports/1/exports \
//                              [--method POST] [--decoy-method POST] [--data '{"format":"csv"}']
//                              [-H 'Authorization: Bearer ...'] [--identical] [--runs 5]
//                              [--ignore-header x-foo] [--json]
//
// Sends the same request to both URLs over raw HTTP, so header names keep their case and order
// as the server wrote them. Reports differences in the status line, header names (presence,
// case, order), header values, body bytes, JSON key order and values, stability across runs,
// and median latency (requests interleaved). Only the values of inherently per-request headers
// (date, request ids, etag, content-length...) are ignored; their presence is still compared.
//
// --identical  require byte-identical bodies (use it for anonymous and invalid-token probes,
//              where the decoy and its sibling must answer exactly alike).
//
// Exit code: 0 = no differences, 1 = differences, 2 = usage or network error.
// Node 18+, no dependencies.

import http from 'node:http';
import https from 'node:https';

const VOLATILE_VALUE = new Set([
  'date', 'age', 'etag', 'last-modified', 'expires', 'set-cookie', 'content-length',
  'x-request-id', 'request-id', 'x-correlation-id', 'x-trace-id', 'traceparent', 'tracestate',
  'x-response-time', 'server-timing', 'x-runtime', 'cf-ray', 'x-amzn-requestid', 'x-amz-cf-id',
  'location',
]);
const HOP_BY_HOP = new Set(['connection', 'keep-alive']);

function usage(msg) {
  if (msg) console.error(`error: ${msg}\n`);
  console.error('usage: node compare_responses.mjs --real <url> --decoy <url> [--method M] [--decoy-method M]');
  console.error('                                  [-H "Name: value" ...] [--data <body>] [--identical] [--runs N]');
  console.error('                                  [--ignore-header name] [--json]');
  process.exit(2);
}

function parseArgs(argv) {
  const opts = { headers: {}, runs: 5, method: 'GET', decoyMethod: null, data: undefined, ignore: new Set(), json: false, identical: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) usage(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '--real') opts.real = next();
    else if (a === '--decoy' || a === '--trap') opts.decoy = next();
    else if (a === '--method' || a === '-X') opts.method = next().toUpperCase();
    else if (a === '--decoy-method' || a === '--trap-method') opts.decoyMethod = next().toUpperCase();
    else if (a === '--data' || a === '-d') opts.data = next();
    else if (a === '--runs') opts.runs = Math.max(1, Number(next()) || 1);
    else if (a === '--ignore-header') opts.ignore.add(next().toLowerCase());
    else if (a === '--identical') opts.identical = true;
    else if (a === '--json') opts.json = true;
    else if (a === '-H' || a === '--header') {
      const h = next();
      const c = h.indexOf(':');
      if (c < 1) usage(`bad header: ${h}`);
      opts.headers[h.slice(0, c).trim()] = h.slice(c + 1).trim();
    } else if (a === '-h' || a === '--help') usage();
    else usage(`unknown argument ${a}`);
  }
  if (!opts.real || !opts.decoy) usage('--real and --decoy are required');
  if (opts.data !== undefined && !Object.keys(opts.headers).some((k) => k.toLowerCase() === 'content-type')) {
    opts.headers['Content-Type'] = 'application/json';
  }
  return opts;
}

// One request over raw HTTP. rawHeaders keeps the server's order and case.
function send(url, method, opts) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const headers = { ...opts.headers };
    const body = method === 'GET' || method === 'HEAD' ? undefined : opts.data;
    if (body !== undefined) headers['Content-Length'] = Buffer.byteLength(body);
    const t0 = performance.now();
    const req = lib.request(u, { method, headers, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = res.rawHeaders;
        const pairs = [];
        for (let i = 0; i < raw.length; i += 2) pairs.push([raw[i], raw[i + 1]]);
        resolve({
          status: res.statusCode,
          reason: res.statusMessage,
          headers: pairs,
          body: Buffer.concat(chunks).toString('utf8'),
          ms: performance.now() - t0,
        });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function parseJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
}

// Structure with key order kept: object keys in the order the server wrote them, array element
// shapes, primitive types. Two bodies with the same data in a different key order differ here.
function shape(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return v.length ? [shape(v[0])] : ['<empty>'];
  if (typeof v === 'object') return Object.fromEntries(Object.keys(v).map((k) => [k, shape(v[k])]));
  return typeof v;
}

function diffShapes(a, b, p = '$', out = []) {
  const kind = (x) => (Array.isArray(x) ? 'array' : typeof x === 'object' ? 'object' : x);
  const ka = kind(a);
  const kb = kind(b);
  if (ka !== kb) {
    out.push(`${p}: real=${JSON.stringify(ka)} decoy=${JSON.stringify(kb)}`);
    return out;
  }
  if (ka === 'array') {
    if (a[0] === '<empty>' || b[0] === '<empty>') return out;
    return diffShapes(a[0], b[0], `${p}[0]`, out);
  }
  if (ka === 'object') {
    const ak = Object.keys(a);
    const bk = Object.keys(b);
    for (const k of ak) if (!bk.includes(k)) out.push(`${p}.${k}: only in real`);
    for (const k of bk) if (!ak.includes(k)) out.push(`${p}.${k}: only in decoy`);
    const common = ak.filter((k) => bk.includes(k));
    const bOrder = bk.filter((k) => ak.includes(k));
    if (common.join() !== bOrder.join()) out.push(`${p}: key order real=[${common}] decoy=[${bOrder}]`);
    for (const k of common) diffShapes(a[k], b[k], `${p}.${k}`, out);
  }
  return out;
}

// Leaf values that differ, for reading (expected for messages that name a different feature).
function diffValues(a, b, p = '$', out = []) {
  if (a && b && typeof a === 'object' && typeof b === 'object' && Array.isArray(a) === Array.isArray(b)) {
    for (const k of Object.keys(a)) if (k in b) diffValues(a[k], b[k], `${p}.${k}`, out);
  } else if (JSON.stringify(a) !== JSON.stringify(b)) {
    out.push(`${p}: real=${JSON.stringify(a)} decoy=${JSON.stringify(b)}`);
  }
  return out;
}

const median = (xs) => {
  const s = [...xs].sort((x, y) => x - y);
  return s[Math.floor(s.length / 2)];
};

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const decoyMethod = opts.decoyMethod || opts.method;
  const realRuns = [];
  const decoyRuns = [];
  try {
    // Interleaved, alternating which goes first, so warm-up and drift hit both alike.
    for (let i = 0; i < opts.runs; i++) {
      if (i % 2 === 0) {
        realRuns.push(await send(opts.real, opts.method, opts));
        decoyRuns.push(await send(opts.decoy, decoyMethod, opts));
      } else {
        decoyRuns.push(await send(opts.decoy, decoyMethod, opts));
        realRuns.push(await send(opts.real, opts.method, opts));
      }
    }
  } catch (e) {
    console.error(`request failed: ${e.message}`);
    process.exit(2);
  }
  const real = realRuns[0];
  const decoy = decoyRuns[0];
  const problems = [];
  const notes = [];

  if (real.status !== decoy.status || real.reason !== decoy.reason) {
    problems.push(`status line: real=${real.status} ${real.reason} decoy=${decoy.status} ${decoy.reason}`);
  }

  // Header names: presence, case and order. Values: everything but per-request values.
  const keep = ([name]) => !HOP_BY_HOP.has(name.toLowerCase()) && !opts.ignore.has(name.toLowerCase());
  const rh = real.headers.filter(keep);
  const dh = decoy.headers.filter(keep);
  const rNames = rh.map(([n]) => n);
  const dNames = dh.map(([n]) => n);
  const lower = (xs) => xs.map((x) => x.toLowerCase());
  for (const n of rNames) if (!lower(dNames).includes(n.toLowerCase())) problems.push(`header only in real: ${n}: ${rh.find(([x]) => x === n)[1]}`);
  for (const n of dNames) if (!lower(rNames).includes(n.toLowerCase())) problems.push(`header only in decoy: ${n}: ${dh.find(([x]) => x === n)[1]}`);
  const rCommon = rNames.filter((n) => lower(dNames).includes(n.toLowerCase()));
  const dCommon = dNames.filter((n) => lower(rNames).includes(n.toLowerCase()));
  if (rCommon.join('\n') !== dCommon.join('\n')) {
    if (lower(rCommon).join() === lower(dCommon).join()) problems.push(`header name case differs: real=[${rCommon}] decoy=[${dCommon}]`);
    else problems.push(`header order differs: real=[${rCommon}] decoy=[${dCommon}]`);
  }
  for (const [n, v] of rh) {
    const other = dh.find(([x]) => x.toLowerCase() === n.toLowerCase());
    if (other && !VOLATILE_VALUE.has(n.toLowerCase()) && other[1] !== v) problems.push(`header value differs: ${n}: real=${v} decoy=${other[1]}`);
  }

  // Body.
  const rj = parseJson(real.body);
  const dj = parseJson(decoy.body);
  let valueDiffs = [];
  if (opts.identical) {
    if (real.body !== decoy.body) problems.push(`bodies are not byte-identical (real ${real.body.length} bytes, decoy ${decoy.body.length} bytes)`);
  }
  if (rj.ok && dj.ok) {
    for (const d of diffShapes(shape(rj.value), shape(dj.value))) problems.push(`body: ${d}`);
    valueDiffs = diffValues(rj.value, dj.value);
    if (!opts.identical && real.body !== decoy.body && JSON.stringify(rj.value) === JSON.stringify(dj.value)) {
      problems.push('body: same JSON, different bytes (spacing, escaping or a trailing newline)');
    }
  } else if (rj.ok !== dj.ok) {
    problems.push(`body: real is ${rj.ok ? 'JSON' : 'not JSON'}, decoy is ${dj.ok ? 'JSON' : 'not JSON'}`);
  } else if (!opts.identical && real.body !== decoy.body) {
    notes.push(`text bodies differ (real ${real.body.length} bytes, decoy ${decoy.body.length} bytes)`);
  }

  // Stability: a decoy whose body changes between identical requests, when the real one doesn't.
  const varies = (runs) => new Set(runs.map((r) => r.body)).size > 1;
  if (varies(decoyRuns) && !varies(realRuns)) problems.push('decoy body changes between identical requests; the real one does not');

  // Latency.
  const rMs = median(realRuns.map((r) => r.ms));
  const dMs = median(decoyRuns.map((r) => r.ms));
  const gap = dMs - rMs;
  if (opts.runs >= 5 && Math.abs(gap) > 1 && Math.abs(gap) / Math.max(rMs, dMs) > 0.25) {
    notes.push(`latency differs by ${gap.toFixed(1)} ms (${(100 * Math.abs(gap) / Math.max(rMs, dMs)).toFixed(0)}%); confirm with more --runs before treating it as a tell`);
  }

  const result = {
    real: { url: opts.real, method: opts.method, status: real.status, headers: real.headers, body: real.body.slice(0, 600), medianMs: +rMs.toFixed(2) },
    decoy: { url: opts.decoy, method: decoyMethod, status: decoy.status, headers: decoy.headers, body: decoy.body.slice(0, 600), medianMs: +dMs.toFixed(2) },
    problems,
    valueDiffs,
    notes,
    match: problems.length === 0,
  };

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`real:  ${opts.method} ${opts.real}`);
    console.log(`decoy: ${decoyMethod} ${opts.decoy}\n`);
    console.log(problems.length ? 'Differences' : 'Differences\n  none');
    for (const p of problems) console.log(`  DIFF  ${p}`);
    if (valueDiffs.length) {
      console.log('\nValues that differ (expected only where the decoy names its own feature or final denial)');
      for (const v of valueDiffs) console.log(`  ${v}`);
    }
    for (const n of notes) console.log(`\nnote: ${n}`);
    console.log(`\nlatency: real=${rMs.toFixed(2)} ms decoy=${dMs.toFixed(2)} ms (median of ${opts.runs}, interleaved)`);
    if (real.body !== decoy.body) {
      console.log(`\nreal  ${real.status}: ${result.real.body}`);
      console.log(`decoy ${decoy.status}: ${result.decoy.body}`);
    }
    console.log(`\nResult: ${result.match ? 'MATCH' : 'DIFFERENT'}`);
  }
  process.exit(result.match ? 0 : 1);
}

main();
