import { readFileSync, readdirSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const valueAfter = (flag, fallback) => {
  const index = process.argv.indexOf(flag);
  return index === -1 ? fallback : process.argv[index + 1];
};
const root = resolve(valueAfter('--root', process.cwd()));
const config = JSON.parse(readFileSync(resolve(
  root,
  valueAfter('--config', 'decision-architecture-allowlist.json'),
), 'utf8'));
const blocking = process.argv.includes('--blocking');
const walk = (directory) => {
  const files = [];
  const visit = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const child = resolve(current, entry.name);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile() && entry.name.endsWith('.rs')) files.push(child);
    }
  };
  visit(directory);
  return files;
};
const ruleSets = config.ruleSets ?? [{
  name: 'legacy-execution-boundary',
  paths: config.executionPaths,
  allowedFiles: [],
  forbiddenIdentifiers: config.forbiddenIdentifiers,
}];
const violations = [];
for (const ruleSet of ruleSets) {
  const allowedFiles = new Set(ruleSet.allowedFiles ?? []);
  for (const scanPath of ruleSet.paths) {
    for (const file of walk(resolve(root, scanPath))) {
      const repoPath = relative(root, file).split('\\').join('/');
      if (allowedFiles.has(repoPath)) continue;
      const lines = readFileSync(file, 'utf8').split('\n');
      for (let index = 0; index < lines.length; index += 1) {
        for (const identifier of ruleSet.forbiddenIdentifiers) {
          if (new RegExp(`\\b${identifier}\\b`).test(lines[index])) {
            violations.push(`${repoPath}:${index + 1}:${ruleSet.name}:${identifier}`);
          }
        }
      }
    }
  }
}
if (violations.length === 0) {
  console.log('decision-architecture-gate: 0 violations');
  process.exit(0);
}
console.error(`decision-architecture-gate: ${violations.length} violation(s)`);
for (const violation of violations) console.error(violation);
process.exit(blocking ? 1 : 0);
