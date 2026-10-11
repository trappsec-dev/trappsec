#!/usr/bin/env node
// Compare a decoy's response with a real endpoint's, the way a careful tester would.
//
//   node compare_responses.mjs --real http://localhost:3000/api/v2/reports/1 \
//                              --trap http://localhost:3000/api/v2/reports/1/exports \
//                              [--method POST] [--data '{"format":"csv"}'] [-H 'Authorization: Bearer ...']
//                              [--trap-method POST] [--runs 5] [--ignore-header x-foo] [--json]
//
// Sends the same request to both URLs and reports differences in status, content type,
// header names, body (exact and JSON shape) and median latency. Volatile headers
// (date, request ids, etag, content-length, ...) are ignored.
//
// Exit code: 0 = status, content type and body shape match; 1 = they differ; 2 = usage or network error.
// Node 18+, no dependencies.

const VOLATILE = new Set([
  'date', 'age', 'etag', 'last-modified', 'content-length', 'expires', 'set-cookie',
  'x-request-id', 'request-id', 'x-correlation-id', 'x-trace-id', 'traceparent', 'tracestate',
  'x-response-time', 'server-timing', 'x-runtime', 'cf-ray', 'x-amzn-requestid', 'x-amz-cf-id',
  'x-cache', 'via', 'connection', 'keep-alive', 'transfer-encoding', 'vary',
]);

function usage(msg) {
  if (msg) console.error(`error: ${msg}\n`);
  console.error('usage: node compare_responses.mjs --real <url> --trap <url> [--method M] [--trap-method M]');
  console.error('                                  [-H "Name: value" ...] [--data <body>] [--runs N] [--ignore-header name] [--json]');
  process.exit(2);
}

function parseArgs(argv) {
  const opts = { headers: {}, runs: 3, method: 'GET', trapMethod: null, data: undefined, ignore: new Set(), json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) usage(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '--real') opts.real = next();
    else if (a === '--trap') opts.trap = next();
    else if (a === '--method' || a === '-X') opts.method = next().toUpperCase();
    else if (a === '--trap-method') opts.trapMethod = next().toUpperCase();
    else if (a === '--data' || a === '-d') opts.data = next();
    else if (a === '--runs') opts.runs = Math.max(1, Number(next()) || 1);
    else if (a === '--ignore-header') opts.ignore.add(next().toLowerCase());
    else if (a === '--json') opts.json = true;
    else if (a === '-H' || a === '--header') {
      const h = next();
      const c = h.indexOf(':');
      if (c < 1) usage(`bad header: ${h}`);
      opts.headers[h.slice(0, c).trim()] = h.slice(c + 1).trim();
    } else if (a === '-h' || a === '--help') usage();
    else usage(`unknown argument ${a}`);
  }
  if (!opts.real || !opts.trap) usage('--real and --trap are required');
  if (opts.data !== undefined && !Object.keys(opts.headers).some((k) => k.toLowerCase() === 'content-type')) {
    opts.headers['Content-Type'] = 'application/json';
  }
  return opts;
}

async function probe(url, method, opts) {
  const times = [];
  let first = null;
  for (let i = 0; i < opts.runs; i++) {
    const t0 = performance.now();
    const res = await fetch(url, {
      method,
      headers: opts.headers,
      body: method === 'GET' || method === 'HEAD' ? undefined : opts.data,
      redirect: 'manual',
    });
    const body = await res.text();
    times.push(performance.now() - t0);
    if (!first) {
      const headers = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      first = { status: res.status, headers, body };
    }
  }
  times.sort((a, b) => a - b);
  return { ...first, medianMs: times[Math.floor(times.length / 2)] };
}

function parseJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
}

// A shape is the structure without the values: object keys, array element shapes, primitive types.
function shape(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return v.length ? [shape(v[0])] : ['<empty>'];
  if (typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = shape(v[k]);
    return out;
  }
  return typeof v;
}

function diffShapes(a, b, p = '$', out = []) {
  const kind = (x) => (Array.isArray(x) ? 'array' : typeof x === 'object' ? 'object' : x);
  const ka = kind(a);
  const kb = kind(b);
  if (ka !== kb) {
    out.push(`${p}: real=${JSON.stringify(ka)} trap=${JSON.stringify(kb)}`);
    return out;
  }
  if (ka === 'array') {
    if (a[0] === '<empty>' || b[0] === '<empty>') return out;
    return diffShapes(a[0], b[0], `${p}[0]`, out);
  }
  if (ka === 'object') {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const k of [...keys].sort()) {
      if (!(k in a)) out.push(`${p}.${k}: only in trap`);
      else if (!(k in b)) out.push(`${p}.${k}: only in real`);
      else diffShapes(a[k], b[k], `${p}.${k}`, out);
    }
  }
  return out;
}

const normType = (ct) => (ct || '').toLowerCase().replace(/\s+/g, '');

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  let real;
  let trap;
  try {
    real = await probe(opts.real, opts.method, opts);
    trap = await probe(opts.trap, opts.trapMethod || opts.method, opts);
  } catch (e) {
    console.error(`request failed: ${e.message}`);
    process.exit(2);
  }

  const ignore = (h) => VOLATILE.has(h) || opts.ignore.has(h);
  const realHeaders = Object.keys(real.headers).filter((h) => !ignore(h));
  const trapHeaders = Object.keys(trap.headers).filter((h) => !ignore(h));
  const onlyReal = realHeaders.filter((h) => !(h in trap.headers));
  const onlyTrap = trapHeaders.filter((h) => !(h in real.headers));
  const differingValues = realHeaders
    .filter((h) => h in trap.headers && h !== 'content-type' && real.headers[h] !== trap.headers[h])
    .map((h) => ({ header: h, real: real.headers[h], trap: trap.headers[h] }));

  const rj = parseJson(real.body);
  const tj = parseJson(trap.body);
  let shapeDiffs = [];
  let bodyKind;
  if (rj.ok && tj.ok) {
    bodyKind = 'json';
    shapeDiffs = diffShapes(shape(rj.value), shape(tj.value));
    // Same data, different bytes (spacing, key order, escaping) is visible to anyone diffing raw responses.
    if (!shapeDiffs.length && real.body !== trap.body && JSON.stringify(rj.value) === JSON.stringify(tj.value)) {
      shapeDiffs.push('same JSON, different serialization (spacing, key order or escaping): compare the raw bodies below');
    }
  } else if (rj.ok !== tj.ok) {
    bodyKind = 'mixed';
    shapeDiffs = [`real body is ${rj.ok ? 'JSON' : 'not JSON'}, trap body is ${tj.ok ? 'JSON' : 'not JSON'}`];
  } else {
    bodyKind = 'text';
    if (real.body !== trap.body) shapeDiffs = [`text bodies differ (real ${real.body.length} bytes, trap ${trap.body.length} bytes)`];
  }

  const result = {
    real: { url: opts.real, status: real.status, contentType: real.headers['content-type'] || null, medianMs: +real.medianMs.toFixed(1), body: real.body.slice(0, 400) },
    trap: { url: opts.trap, status: trap.status, contentType: trap.headers['content-type'] || null, medianMs: +trap.medianMs.toFixed(1), body: trap.body.slice(0, 400) },
    statusMatch: real.status === trap.status,
    contentTypeMatch: normType(real.headers['content-type']) === normType(trap.headers['content-type']),
    bodyIdentical: real.body === trap.body,
    bodyKind,
    shapeDiffs,
    headersOnlyInReal: onlyReal,
    headersOnlyInTrap: onlyTrap,
    headerValueDiffs: differingValues,
  };
  result.match = result.statusMatch && result.contentTypeMatch && shapeDiffs.length === 0;

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    const mark = (ok) => (ok ? 'same ' : 'DIFF ');
    console.log(`real: ${opts.method} ${opts.real}`);
    console.log(`trap: ${opts.trapMethod || opts.method} ${opts.trap}\n`);
    console.log(`${mark(result.statusMatch)} status        real=${real.status} trap=${trap.status}`);
    console.log(`${mark(result.contentTypeMatch)} content-type  real=${result.real.contentType} trap=${result.trap.contentType}`);
    console.log(`${mark(shapeDiffs.length === 0)} body shape    ${bodyKind}${result.bodyIdentical ? ' (byte-identical)' : ''}`);
    for (const d of shapeDiffs) console.log(`        ${d}`);
    console.log(`${mark(!onlyReal.length && !onlyTrap.length)} header names  ${onlyReal.length || onlyTrap.length ? '' : '(ignoring volatile headers)'}`);
    for (const h of onlyReal) console.log(`        only in real: ${h}: ${real.headers[h]}`);
    for (const h of onlyTrap) console.log(`        only in trap: ${h}: ${trap.headers[h]}`);
    for (const d of differingValues) console.log(`        value differs: ${d.header}: real=${d.real} trap=${d.trap}`);
    console.log(`      latency       real=${result.real.medianMs}ms trap=${result.trap.medianMs}ms (median of ${opts.runs})`);
    if (!result.bodyIdentical) {
      console.log(`\nreal body: ${result.real.body}`);
      console.log(`trap body: ${result.trap.body}`);
    }
    console.log(`\nResult: ${result.match ? 'MATCH' : 'DIFFERENT'}${onlyReal.length || onlyTrap.length ? ' (header differences listed above; per-handler headers are a known trappsec limitation)' : ''}`);
  }
  process.exit(result.match ? 0 : 1);
}

main();
