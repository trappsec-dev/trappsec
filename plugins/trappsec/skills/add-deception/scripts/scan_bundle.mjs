#!/usr/bin/env node
// Scan a production frontend build for lure survival and tells.
//
//   node scan_bundle.mjs --dir dist --lure "/api/v2/exports" --lure "bulkExportBeta" [--json] [--verbose]
//
// For every --lure string: is it present in the shipped files (or was it tree-shaken)?
// For every shipped file: are there words or phrases that reveal intent (decoy, honeypot,
// "never enabled", "do not remove", ...), and how close are they to a lure? Do shipped file
// and chunk names reveal intent? Source maps are inspected the way an attacker holding
// them would: original file of each lure, comments and revealing words around it.
//
// Exit code: 0 = every lure found and no HIGH findings, 1 = otherwise, 2 = usage error.
// Node 18+, no dependencies.

import fs from 'node:fs';
import path from 'node:path';

const STRONG = ['decoy', 'honeypot', 'honeyfield', 'honeytoken', 'tripwire', 'lure', 'canarytoken', 'deception', 'deceptive'];
const WEAK = ['trap', 'honey', 'bait', 'canary', 'fake', 'dummy', 'ghost', 'sensor', 'mock', 'bogus', 'sham', 'phony', 'snare'];
// Phrases a teammate writes next to a deliberate lure; they reveal it as surely as a word.
const PHRASES = [
  /do not (use|call|remove|delete|touch|ship)/i, /don'?t (use|call|remove|delete|touch)/i, /never (enabled|called|used|shipped)/i,
  /remove (this )?before (prod|production|release|launch)/i, /internal[ _-]?(debug|only)/i, /debug[ _-]?only/i,
  /security (team|sensor|tripwire|trap)/i, /\bon purpose\b/i, /\bintentionally (unused|uncalled|disabled)/i, /not (wired|hooked) up/i,
];
const TEXT_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.css', '.html', '.htm', '.json', '.map', '.txt', '.xml', '.svg', '.webmanifest']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'cache']);

function usage(msg) {
  if (msg) console.error(`error: ${msg}\n`);
  console.error('usage: node scan_bundle.mjs --dir <build-output> [--dir ...] --lure <string> [--lure ...]');
  console.error('                            [--lures-file <file>] [--proximity <chars>] [--json] [--verbose]');
  process.exit(2);
}

function parseArgs(argv) {
  const opts = { dirs: [], lures: [], proximity: 600, json: false, verbose: false, maxBytes: 25 * 1024 * 1024 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) usage(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '--dir') opts.dirs.push(next());
    else if (a === '--lure') opts.lures.push(next());
    else if (a === '--lures-file') {
      for (const line of fs.readFileSync(next(), 'utf8').split(/\r?\n/)) if (line.trim()) opts.lures.push(line.trim());
    } else if (a === '--proximity') opts.proximity = Number(next());
    else if (a === '--json') opts.json = true;
    else if (a === '--verbose') opts.verbose = true;
    else if (a === '-h' || a === '--help') usage();
    else usage(`unknown argument ${a}`);
  }
  if (!opts.dirs.length) usage('at least one --dir is required (e.g. dist, build, .next/static, out)');
  for (const d of opts.dirs) if (!fs.existsSync(d) || !fs.statSync(d).isDirectory()) usage(`not a directory: ${d}`);
  if (!opts.lures.length) console.error('warning: no --lure given; only scanning for revealing words\n');
  return opts;
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(p, out);
    } else if (entry.isFile() && TEXT_EXT.has(path.extname(entry.name).toLowerCase())) {
      out.push(p);
    }
  }
  return out;
}

const isLetter = (c) => /[A-Za-z]/.test(c || '');
const isUpper = (c) => /[A-Z]/.test(c || '');
const isLower = (c) => /[a-z]/.test(c || '');

// Whole-word matches that respect camelCase, snake_case and kebab-case boundaries,
// so "focusTrap" and "is_decoy" match while "bootstrap" and "failure" do not.
function wordHits(text, word) {
  const hits = [];
  const re = new RegExp(word, 'gi');
  let m;
  while ((m = re.exec(text))) {
    const s = m.index;
    const e = s + word.length;
    const before = text[s - 1];
    const startOk = !isLetter(before) || (isLower(before) && isUpper(text[s]));
    let endOk = !isLetter(text[e]) || (isUpper(text[e]) && isLower(text[e - 1]));
    if (!endOk && (text[e] === 's' || text[e] === 'S')) {
      endOk = !isLetter(text[e + 1]) || isUpper(text[e + 1]);
    }
    if (startOk && endOk) hits.push(s);
  }
  return hits;
}

function allIndexes(text, needle) {
  const out = [];
  if (!needle) return out;
  let i = text.indexOf(needle);
  while (i !== -1) {
    out.push(i);
    i = text.indexOf(needle, i + needle.length);
  }
  return out;
}

const snippet = (text, i, len = 70) =>
  text.slice(Math.max(0, i - len), Math.min(text.length, i + len)).replace(/\s+/g, ' ').trim();

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function scanPhrases(text) {
  const hits = [];
  for (const re of PHRASES) {
    const g = new RegExp(re.source, 'gi');
    let m;
    while ((m = g.exec(text))) hits.push({ word: m[0], index: m.index, strength: 'phrase' });
  }
  return hits;
}

function scanVocab(text) {
  const hits = [];
  for (const w of STRONG) for (const i of wordHits(text, w)) hits.push({ word: w, index: i, strength: 'strong' });
  for (const w of WEAK) for (const i of wordHits(text, w)) hits.push({ word: w, index: i, strength: 'weak' });
  return hits;
}

function inlineSourceMap(text) {
  const m = text.match(/sourceMappingURL=data:application\/json[^,]*;base64,([A-Za-z0-9+/=]+)/);
  if (!m) return null;
  try {
    return JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

// Lines that carry a comment (ignoring the "//" inside URLs such as https://).
function commentLines(lines) {
  return lines.filter(({ text }) => /(^|[^:])\/\/|\/\*|\*\/|^\s*\*|<!--/.test(text));
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const files = opts.dirs.flatMap((d) => walk(d));
  const result = {
    scanned: { files: 0, bytes: 0, dirs: opts.dirs },
    lures: opts.lures.map((l) => ({ lure: l, files: [], occurrences: 0, sourceOrigins: [] })),
    findings: [],
    weakFar: {},
    sourceMaps: { files: [], inline: [] },
    skipped: [],
  };

  const maps = [];

  for (const file of files) {
    const stat = fs.statSync(file);
    if (stat.size > opts.maxBytes) {
      result.skipped.push(file);
      continue;
    }
    const text = fs.readFileSync(file, 'utf8');
    result.scanned.files++;
    result.scanned.bytes += stat.size;
    const rel = path.relative(process.cwd(), file);

    if (file.endsWith('.map')) {
      try {
        maps.push({ file: rel, map: JSON.parse(text) });
        result.sourceMaps.files.push(rel);
      } catch {
        result.skipped.push(file);
      }
      continue;
    }
    const inline = inlineSourceMap(text);
    if (inline) {
      maps.push({ file: `${rel} (inline map)`, map: inline });
      result.sourceMaps.inline.push(rel);
    }

    const lureHits = [];
    result.lures.forEach((l, li) => {
      const idx = allIndexes(text, l.lure);
      if (idx.length) {
        l.files.push(rel);
        l.occurrences += idx.length;
        for (const i of idx) lureHits.push({ lure: li, index: i });
      }
    });

    // File and chunk names ship too (AdminTools-3f9a.js); check them like identifiers.
    for (const w of STRONG.concat(WEAK)) {
      if (wordHits(path.basename(file), w).length) {
        const strong = STRONG.includes(w) || lureHits.length > 0;
        result.findings.push({
          severity: strong ? 'HIGH' : 'MEDIUM',
          file: rel,
          offset: 0,
          word: w,
          reason: lureHits.length ? 'revealing word in the name of a file that holds a lure' : 'revealing word in a shipped file name',
          context: path.basename(file),
        });
      }
    }

    for (const hit of scanPhrases(text)) {
      const near = lureHits.some((h) => Math.abs(h.index - hit.index) <= opts.proximity);
      if (near) {
        result.findings.push({ severity: 'HIGH', file: rel, offset: hit.index, word: hit.word, reason: 'revealing phrase near a lure', context: snippet(text, hit.index) });
      }
    }

    for (const hit of scanVocab(text)) {
      // Minified bundles pack unrelated modules side by side, so weak words (often library
      // code such as focusTrap) only count as HIGH when they sit right next to a lure.
      const nearest = lureHits.reduce((best, h) => {
        const d = Math.abs(h.index - hit.index);
        return !best || d < best.d ? { d, lure: h.lure } : best;
      }, null);
      const highWindow = hit.strength === 'strong' ? opts.proximity : Math.min(120, opts.proximity);
      const isHigh = nearest && nearest.d <= highWindow;
      const isNear = nearest && nearest.d <= opts.proximity;
      if (isHigh || isNear) {
        result.findings.push({
          severity: isHigh ? 'HIGH' : 'MEDIUM',
          file: rel,
          offset: hit.index,
          word: hit.word,
          reason: `revealing word ${nearest.d} chars from lure "${result.lures[nearest.lure].lure}"`,
          context: snippet(text, hit.index),
        });
      } else if (hit.strength === 'strong') {
        result.findings.push({
          severity: 'MEDIUM',
          file: rel,
          offset: hit.index,
          word: hit.word,
          reason: 'strong revealing word in a shipped file (far from lures; check whether it is yours or a library\'s)',
          context: snippet(text, hit.index),
        });
      } else {
        result.weakFar[hit.word] = (result.weakFar[hit.word] || 0) + 1;
        if (opts.verbose) {
          result.findings.push({ severity: 'LOW', file: rel, offset: hit.index, word: hit.word, reason: 'weak word far from lures', context: snippet(text, hit.index) });
        }
      }
    }
  }

  // Source maps: where each lure originates, and what an attacker with the maps sees around it.
  for (const { file, map } of maps) {
    const sources = Array.isArray(map.sources) ? map.sources : [];
    const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
    sources.forEach((src, si) => {
      const strongInPath = STRONG.concat(WEAK).filter((w) => wordHits(String(src), w).length);
      const content = typeof contents[si] === 'string' ? contents[si] : null;
      let lureHere = false;
      if (content) {
        const lines = content.split(/\r?\n/);
        result.lures.forEach((l) => {
          for (const i of allIndexes(content, l.lure)) {
            lureHere = true;
            const ln = lineOf(content, i);
            const window = [];
            for (let k = Math.max(1, ln - 5); k <= Math.min(lines.length, ln + 5); k++) window.push({ n: k, text: lines[k - 1] });
            const comments = commentLines(window);
            const vocab = window.flatMap(({ n, text }) => scanVocab(text).concat(scanPhrases(text)).map((h) => ({ n, word: h.word, text })));
            l.sourceOrigins.push({ map: file, source: src, line: ln, comments });
            for (const v of vocab) {
              result.findings.push({
                severity: 'HIGH',
                file: `${src} (via ${file})`,
                offset: v.n,
                word: v.word,
                reason: `revealing word or phrase within 5 lines of lure "${l.lure}" in original source`,
                context: v.text.trim().slice(0, 160),
              });
            }
          }
        });
      }
      for (const w of strongInPath) {
        const strong = STRONG.includes(w);
        if (lureHere || strong) {
          result.findings.push({
            severity: lureHere ? 'HIGH' : 'MEDIUM',
            file: `${src} (via ${file})`,
            offset: 0,
            word: w,
            reason: lureHere ? 'revealing word in the file path of a lure\'s source' : 'revealing word in an original source path',
            context: String(src),
          });
        }
      }
    });
  }

  const missing = result.lures.filter((l) => !l.files.length);
  const high = result.findings.filter((f) => f.severity === 'HIGH');
  result.pass = missing.length === 0 && high.length === 0;

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    report(result, opts);
  }
  process.exit(result.pass ? 0 : 1);
}

function report(r, opts) {
  const mb = (r.scanned.bytes / 1024 / 1024).toFixed(1);
  console.log(`scan_bundle: ${r.scanned.files} files (${mb} MB) in ${r.scanned.dirs.join(', ')}\n`);

  if (r.lures.length) {
    console.log('Lures');
    for (const l of r.lures) {
      if (l.files.length) {
        const shown = l.files.slice(0, 3).join(', ') + (l.files.length > 3 ? `, +${l.files.length - 3} more` : '');
        console.log(`  FOUND    ${l.lure}  (${l.occurrences}x in ${l.files.length} file(s): ${shown})`);
      } else {
        console.log(`  MISSING  ${l.lure}  (not in any shipped file: tree-shaken, dead-code-eliminated, server-only, or a template-literal split; try a shorter static part)`);
      }
    }
    console.log('');
  }

  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  const findings = [...r.findings].sort((a, b) => order[a.severity] - order[b.severity]);
  console.log('Findings');
  if (!findings.length) console.log('  none');
  for (const f of findings) {
    console.log(`  ${f.severity.padEnd(6)} ${f.file} @ ${f.offset}: "${f.word}" (${f.reason})`);
    console.log(`         ${f.context}`);
  }
  const weak = Object.entries(r.weakFar);
  if (weak.length && !opts.verbose) {
    const total = weak.reduce((s, [, n]) => s + n, 0);
    console.log(`  LOW    ${total} weak-word occurrence(s) far from any lure (${weak.map(([w, n]) => `${w} x${n}`).join(', ')}); usually library code. --verbose lists them.`);
  }
  console.log('');

  const mapCount = r.sourceMaps.files.length + r.sourceMaps.inline.length;
  console.log('Source maps');
  if (!mapCount) {
    console.log('  none in the build output');
  } else {
    if (r.sourceMaps.files.length) console.log(`  ${r.sourceMaps.files.length} .map file(s). If they are deployed, original file paths and comments are public.`);
    if (r.sourceMaps.inline.length) console.log(`  ${r.sourceMaps.inline.length} file(s) embed an inline source map: original source ships to every browser.`);
    for (const l of r.lures) {
      for (const o of l.sourceOrigins.slice(0, 5)) {
        console.log(`  "${l.lure}" originates in ${o.source}:${o.line}`);
        for (const c of o.comments) console.log(`      ${String(c.n).padStart(5)} | ${c.text.trim().slice(0, 140)}`);
      }
    }
  }
  if (r.skipped.length) console.log(`\nSkipped ${r.skipped.length} file(s) (too large or unparsable): ${r.skipped.slice(0, 5).join(', ')}`);

  const missing = r.lures.filter((l) => !l.files.length).length;
  const high = r.findings.filter((f) => f.severity === 'HIGH').length;
  console.log(`\nResult: ${r.pass ? 'PASS' : 'FAIL'}${missing ? `, ${missing} lure(s) missing` : ''}${high ? `, ${high} HIGH finding(s)` : ''}`);
}

main();
