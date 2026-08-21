import { readFileSync, readdirSync, statSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const args = new Set(process.argv.slice(2));
const failCli = (message) => {
  console.error(`decision-literal-gate: CLI error: ${message}`);
  process.exit(2);
};
const valueAfter = (flag, fallback) => {
  const index = process.argv.indexOf(flag);
  if (index === -1) return fallback;
  const value = process.argv[index + 1];
  if (value === undefined || value.startsWith('-')) {
    failCli(`${flag} requires a value`);
  }
  return value;
};
const root = resolve(valueAfter('--root', process.cwd()));
const configPath = resolve(root, valueAfter('--config', 'decision-literal-allowlist.json'));
const blocking = args.has('--blocking');
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const allowed = new Set(config.allowedFiles.map((entry) => entry.path));
const quotedLiteral = /(?:r(#{0,255})"(?:APPROVED|ALLOWED)"\1|(["'`])(?:APPROVED|ALLOWED)\2)/g;

const files = [];
const walk = (absolute) => {
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    const child = resolve(absolute, entry.name);
    if (entry.isDirectory()) walk(child);
    else if (entry.isFile() && entry.name.endsWith('.rs')) files.push(child);
  }
};
for (const runtimePath of config.runtimePaths) {
  const absolute = resolve(root, runtimePath);
  if (statSync(absolute).isDirectory()) walk(absolute);
  else if (absolute.endsWith('.rs')) files.push(absolute);
}

const violations = [];
for (const file of files) {
  const repoPath = relative(root, file).split('\\').join('/');
  if (allowed.has(repoPath)) continue;
  const lines = readFileSync(file, 'utf8').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    quotedLiteral.lastIndex = 0;
    if (quotedLiteral.test(lines[index])) {
      violations.push(`${repoPath}:${index + 1}:${lines[index].trim()}`);
    }
  }
}

if (violations.length === 0) {
  console.log('decision-literal-gate: 0 violations');
  process.exit(0);
}
console.error(`decision-literal-gate: ${violations.length} violation(s)`);
for (const violation of violations) console.error(violation);
process.exit(blocking ? 1 : 0);
