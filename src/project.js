import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const managers = [
  ['pnpm-lock.yaml', 'pnpm'], ['package-lock.json', 'npm'], ['yarn.lock', 'yarn'],
];
export function sha256(data) { return `sha256:${crypto.createHash('sha256').update(data).digest('hex')}`; }
export function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
export function detectProject(root) {
  const manifestPath = path.join(root, 'package.json');
  if (!fs.existsSync(manifestPath)) throw new Error(`No package.json found in ${root}. DepGuard 0.1.0 supports npm-family projects only.`);
  const manager = managers.find(([file]) => fs.existsSync(path.join(root, file))) || ['package-lock.json', 'npm'];
  const lockPath = path.join(root, manager[0]);
  const manifest = readJson(manifestPath);
  return { root, manifestPath, manifest, manager: manager[1], lockPath: fs.existsSync(lockPath) ? lockPath : null };
}
export function installedVersion(project, name) {
  if (project.lockPath?.endsWith('package-lock.json')) {
    const lock = readJson(project.lockPath);
    const p = lock.packages?.[`node_modules/${name}`];
    if (p?.version) return p.version;
    if (lock.dependencies?.[name]?.version) return lock.dependencies[name].version;
  }
  const fields = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const field of fields) if (project.manifest[field]?.[name]) return project.manifest[field][name].replace(/^[~^<>=v ]+/, '');
  return null;
}
export function scanProject(root) {
  const project = detectProject(root);
  const dependencies = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].flatMap((kind) =>
    Object.entries(project.manifest[kind] || {}).map(([name, requested]) => ({ name, requested, kind, installed: installedVersion(project, name) })));
  return { kind: 'scan', schemaVersion: '1', project: { packageManager: project.manager, lockfile: project.lockPath ? path.basename(project.lockPath) : null, lockfileDigest: project.lockPath ? sha256(fs.readFileSync(project.lockPath)) : null }, dependencies };
}
export function loadConfig(root) {
  const file = path.join(root, 'depguard.yaml');
  if (!fs.existsSync(file)) return { source: 'defaults', commands: {} };
  // This deliberately small, inspectable parser reads command mappings. Full YAML is not
  // needed for the local MVP and avoids executing deserializers on repository input.
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  const commands = {}; let inCommands = false;
  for (const line of lines) {
    if (/^\s*commands\s*:/.test(line)) { inCommands = true; continue; }
    if (/^\S/.test(line)) inCommands = false;
    if (inCommands) { const match = line.match(/^\s{4,}([\w-]+):\s*(.+)\s*$/); if (match) commands[match[1]] = match[2].replace(/^['"]|['"]$/g, ''); }
  }
  return { source: file, commands };
}
