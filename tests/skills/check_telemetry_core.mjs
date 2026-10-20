#!/usr/bin/env node
// The skills share telemetry text, copied into each skill so every skill stands alone:
// a common core in all three, and a findings core in add-deception and add-detection.
// Fail if the copies drift apart.
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../plugins/trappsec/skills');
const BLOCKS = [
  { name: 'common core', begin: '<!-- BEGIN COMMON CORE', end: '<!-- END COMMON CORE -->', skills: ['add-auditing', 'add-deception', 'add-detection'] },
  { name: 'findings core', begin: '<!-- BEGIN FINDINGS CORE', end: '<!-- END FINDINGS CORE -->', skills: ['add-deception', 'add-detection'] },
];

let failed = false;
for (const block of BLOCKS) {
  const copies = block.skills.map((skill) => {
    const file = path.join(root, skill, 'references', 'telemetry.md');
    const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    const a = text.indexOf(block.begin);
    const b = text.indexOf(block.end);
    if (a === -1 || b === -1) {
      console.error(`${skill}: telemetry.md has no ${block.name} markers`);
      failed = true;
      return null;
    }
    return { skill, text: text.slice(a, b + block.end.length) };
  });
  if (copies.includes(null)) continue;
  const [first, ...rest] = copies;
  const drifted = rest.filter((c) => c.text !== first.text);
  for (const c of drifted) console.error(`${c.skill}: ${block.name} differs from ${first.skill}`);
  if (drifted.length) failed = true;
  else console.log(`${block.name} identical in ${block.skills.join(', ')}`);
}
if (failed) process.exit(1);
