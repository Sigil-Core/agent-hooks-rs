import { readFileSync, readdirSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const failConfiguration = (message) => {
  console.error(`decision-architecture-gate: configuration error: ${message}`);
  process.exit(2);
};
const valueAfter = (flag, fallback) => {
  const index = process.argv.indexOf(flag);
  if (index === -1) return fallback;
  const value = process.argv[index + 1];
  if (value === undefined || value.startsWith('--')) {
    failConfiguration(`${flag} requires a value`);
  }
  return value;
};
const root = resolve(valueAfter('--root', process.cwd()));
const configPath = resolve(
  root,
  valueAfter('--config', 'decision-architecture-allowlist.json'),
);
let config;
try {
  config = JSON.parse(readFileSync(configPath, 'utf8'));
} catch (error) {
  failConfiguration(`cannot read ${configPath}: ${error.message}`);
}
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
const isStringArray = (value) => Array.isArray(value)
  && value.length > 0
  && value.every((entry) => typeof entry === 'string' && entry.length > 0);
if (config === null || typeof config !== 'object' || Array.isArray(config)) {
  failConfiguration('configuration must be an object');
}
let ruleSets;
if (config.ruleSets === undefined) {
  if (!isStringArray(config.executionPaths)) {
    failConfiguration('executionPaths must be a non-empty string array');
  }
  if (!isStringArray(config.forbiddenIdentifiers)) {
    failConfiguration('forbiddenIdentifiers must be a non-empty string array');
  }
  ruleSets = [{
    name: 'legacy-execution-boundary',
    paths: config.executionPaths,
    allowedFiles: [],
    forbiddenIdentifiers: config.forbiddenIdentifiers,
  }];
} else {
  if (!Array.isArray(config.ruleSets) || config.ruleSets.length === 0) {
    failConfiguration('ruleSets must be a non-empty array');
  }
  ruleSets = config.ruleSets;
}
for (const [index, ruleSet] of ruleSets.entries()) {
  if (typeof ruleSet !== 'object' || ruleSet === null || Array.isArray(ruleSet)) {
    failConfiguration(`ruleSets[${index}] must be an object`);
  }
  if (typeof ruleSet.name !== 'string' || ruleSet.name.length === 0) {
    failConfiguration(`ruleSets[${index}].name must be a non-empty string`);
  }
  if (!isStringArray(ruleSet.paths)) {
    failConfiguration(`ruleSets[${index}].paths must be a non-empty string array`);
  }
  if (!isStringArray(ruleSet.forbiddenIdentifiers)) {
    failConfiguration(
      `ruleSets[${index}].forbiddenIdentifiers must be a non-empty string array`,
    );
  }
  if (ruleSet.allowedFiles !== undefined
      && (!Array.isArray(ruleSet.allowedFiles)
        || !ruleSet.allowedFiles.every((entry) => typeof entry === 'string'))) {
    failConfiguration(`ruleSets[${index}].allowedFiles must be a string array`);
  }
}
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
