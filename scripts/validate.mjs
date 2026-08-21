import { readdir, readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { spawnSync } from 'node:child_process';

const roots = ['src', 'dashboard', 'popup', 'tests'];
const jsonFiles = ['manifest.json', 'rules/phishing-rules.json'];
const jsFiles = [];

async function walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (extname(entry.name) === '.js') jsFiles.push(path);
  }
}

for (const root of roots) await walk(root);
let failed = false;
for (const file of jsFiles) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failed = true;
    process.stderr.write(`${file}\n${result.stderr}`);
  }
}
for (const file of jsonFiles) {
  try { JSON.parse(await readFile(file, 'utf8')); }
  catch (error) { failed = true; console.error(`${file}: ${error.message}`); }
}
if (failed) process.exit(1);
console.log(`Validation passed: ${jsFiles.length} JavaScript files and ${jsonFiles.length} JSON files.`);
