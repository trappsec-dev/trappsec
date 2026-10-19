#!/usr/bin/env node
// The three skills share one telemetry core, copied into each skill so every skill
// stands alone. Fail if the copies drift apart.
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../plugins/trappsec/skills');
const BEGIN = '<!-- BEGIN COMMON CORE';
const END = '<!-- END COMMON CORE -->';

const cores = fs.readdirSync(root).sort().flatMap((skill) => {
  const file = path.join(root, skill, 'references', 'telemetry.md');
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const a = text.indexOf(BEGIN);
  const b = text.indexOf(END);
  if (a === -1 || b === -1) {
    console.error(`${skill}: telemetry.md has no common core markers`);
    process.exit(1);
  }
  return [{ skill, core: text.slice(a, b + END.length) }];
});

const [first, ...rest] = cores;
const drifted = rest.filter((c) => c.core !== first.core);
for (const c of drifted) console.error(`${c.skill}: common core differs from ${first.skill}`);
if (drifted.length || cores.length < 2) process.exit(1);
console.log(`common telemetry core identical in ${cores.map((c) => c.skill).join(', ')}`);
