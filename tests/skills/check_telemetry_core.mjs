#!/usr/bin/env node
// The skills share text, copied into each skill so every skill stands alone: in
// references/telemetry.md a common core in add-auditing, add-deception and add-detection and a
// findings core in add-deception and add-detection; the OpenTelemetry prerequisite inside the
// common core, also in add-telemetry's references/setup.md; in references/attack-paths.md the
// attack-paths core in add-deception and add-detection. Fail if the copies drift apart.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../plugins/trappsec/skills');
const BLOCKS = [
  { name: 'prerequisite core', file: { 'add-telemetry': 'setup.md' }, begin: '<!-- BEGIN PREREQUISITE CORE', end: '<!-- END PREREQUISITE CORE -->', skills: ['add-auditing', 'add-deception', 'add-detection', 'add-telemetry'] },
  { name: 'common core', file: 'telemetry.md', begin: '<!-- BEGIN COMMON CORE', end: '<!-- END COMMON CORE -->', skills: ['add-auditing', 'add-deception', 'add-detection'] },
  { name: 'findings core', file: 'telemetry.md', begin: '<!-- BEGIN FINDINGS CORE', end: '<!-- END FINDINGS CORE -->', skills: ['add-deception', 'add-detection'] },
  { name: 'attack paths core', file: 'attack-paths.md', begin: '<!-- BEGIN ATTACK PATHS CORE', end: '<!-- END ATTACK PATHS CORE -->', skills: ['add-deception', 'add-detection'] },
];

let failed = false;
for (const block of BLOCKS) {
  const copies = block.skills.map((skill) => {
    const name = typeof block.file === 'string' ? block.file : block.file[skill] ?? 'telemetry.md';
    const file = path.join(root, skill, 'references', name);
    const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    const a = text.indexOf(block.begin);
    const b = text.indexOf(block.end);
    if (a === -1 || b === -1) {
      console.error(`${skill}: ${name} has no ${block.name} markers`);
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
