#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const ROOT_PACKAGE_PATH = path.resolve(process.cwd(), 'package.json');
const INTERNAL_SCOPE = '@blackveil/';
const ALLOWED_WORKSPACE_SPEC = 'workspace:*';
const SECTIONS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

function isAllowedVersionSpec(version) {
  if (version === ALLOWED_WORKSPACE_SPEC) {
    return true;
  }

  return /^(\^|~)?\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$/.test(version);
}

if (!fs.existsSync(ROOT_PACKAGE_PATH)) {
  console.error(`Root package.json not found at ${ROOT_PACKAGE_PATH}`);
  process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(ROOT_PACKAGE_PATH, 'utf8'));
const violations = [];

for (const section of SECTIONS) {
  const deps = pkg[section];
  if (!deps) continue;

  for (const [name, version] of Object.entries(deps)) {
    if (!name.startsWith(INTERNAL_SCOPE)) continue;

    if (!isAllowedVersionSpec(version)) {
      violations.push(`${section}.${name} uses disallowed version spec: ${version}`);
    }
  }
}

if (violations.length > 0) {
  console.error('Internal dependency policy validation failed.');
  console.error('Use pinned semver ranges or workspace:* for @blackveil/* dependencies.');
  for (const violation of violations) {
    console.error(` - ${violation}`);
  }
  process.exit(1);
}

console.log('Internal dependency policy validation passed.');
