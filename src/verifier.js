import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
import { detectProject, readJson, sha256 } from './project.js';
import { doctor, runHost, runOci } from './sandbox.js';
import { EXIT } from './cli.js';

const ignored = new Set(['node_modules', '.git', '.depguard', '.depguard-home', '.env', '.env.local', '.npmrc']);
function digest(value) { return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`; }
function changes(before, after, field) { const a = before[field] || {}; const b = after[field] || {}; return { added: Object.keys(b).filter((k) => !(k in a)).sort(), removed: Object.keys(a).filter((k) => !(k in b)).sort(), before: Object.keys(a).length, after: Object.keys(b).length }; }
function listScripts(meta) { return Object.keys(meta.scripts || {}).filter((name) => /^(pre|post)?install$/.test(name)).sort(); }
function delta(metadata) {
  const dep = changes(metadata.from, metadata.to, 'dependencies'); const oldScripts = listScripts(metadata.from); const newScripts = listScripts(metadata.to);
  return { dependencies: dep, lifecycleScripts: { before: oldScripts, after: newScripts, added: newScripts.filter((s) => !oldScripts.includes(s)) }, license: { before: metadata.from.license, after: metadata.to.license, changed: metadata.from.license !== metadata.to.license }, metadataAvailable: metadata.from.available && metadata.to.available };
}
function fileTree(root) {
  const out = {};
  function walk(dir, prefix = '') { for (const ent of fs.readdirSync(dir, { withFileTypes: true })) { if (ignored.has(ent.name)) continue; const relative = path.join(prefix, ent.name); const full = path.join(dir, ent.name); if (ent.isDirectory()) walk(full, relative); else if (ent.isFile()) { const data = fs.readFileSync(full); out[relative] = digest(data); } } }
  walk(root); return out;
}
function compareTree(a, b) { const all = new Set([...Object.keys(a), ...Object.keys(b)]); return [...all].filter((file) => a[file] !== b[file]).sort(); }
function statusFor(results, name) { const r = results.find((x) => x.label === name); return !r ? 'not-configured' : r.exitCode === 0 ? 'passed' : 'failed'; }
function testCount(results) { const test = results.find((r) => r.label === 'test'); if (!test) return { status: 'not-configured', total: 0, passed: 0, failed: 0 }; const matches = `${test.stdout}\n${test.stderr}`.match(/# (?:tests|pass) (\d+)/i); return { status: test.exitCode === 0 ? 'passed' : 'failed', total: matches ? Number(matches[1]) : 0, passed: test.exitCode === 0 && matches ? Number(matches[1]) : 0, failed: test.exitCode === 0 ? 0 : 1 }; }
function outcome({ baseline, candidate, packageDelta, environmentFailure }) {
  if (environmentFailure) return { code: 'ENVIRONMENT ERROR', exitCode: EXIT.ENVIRONMENT, rationale: environmentFailure };
  const failed = candidate.some((r) => r.exitCode !== 0);
  if (failed) return { code: 'VERIFICATION FAILED', exitCode: EXIT.FAILED, rationale: 'One or more configured candidate checks failed.' };
  if (packageDelta.lifecycleScripts.added.length || packageDelta.license.changed || packageDelta.dependencies.added.length > 20) return { code: 'REVIEW REQUIRED', exitCode: EXIT.REVIEW, rationale: 'A package or behavior change requires review under the default policy.' };
  return { code: 'VERIFIED AGAINST CONFIGURED CHECKS', exitCode: EXIT.VERIFIED, rationale: 'Configured checks passed and no default review trigger was observed.' };
}
function evidenceId(value) { return digest(JSON.stringify(value)).slice(7, 31); }

export async function verifyTransition({ project, config, spec, metadata, options }) {
  const packageDelta = delta(metadata); const check = await doctor(project); const unsafe = options.unsafeHostExecution;
  if (!unsafe && !check.available) return buildEvidence({ project, spec, metadata, packageDelta, baseline: [], candidate: [], behavior: emptyBehavior(), environmentFailure: 'An OCI sandbox backend is required. Docker or Podman was not reachable. No repository or dependency code was executed.', sandbox: { backend: null, unsafeHostExecution: false } });
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'depguard-'));
  const baselineDir = path.join(root, 'baseline'); const candidateDir = path.join(root, 'candidate');
  try {
    await cp(project.root, baselineDir, { recursive: true, filter: (source) => !ignored.has(path.basename(source)) });
    await cp(project.root, candidateDir, { recursive: true, filter: (source) => !ignored.has(path.basename(source)) });
    updateCandidate(candidateDir, spec.name, spec.toVersion);
    const initialBaseline = fileTree(baselineDir); const initialCandidate = fileTree(candidateDir);
    const commands = commandPlan(detectProject(baselineDir), config, options);
    const exec = unsafe ? runHost : (command, params) => runOci(command, { ...params, backend: check.backend });
    const baseline = await execute(commands, baselineDir, exec); const candidate = await execute(commands, candidateDir, exec);
    const behavior = { observerVersion: 'portable-v1', network: { status: 'not-observed', reason: unsafe ? 'Unsafe host execution does not inspect network traffic.' : 'OCI backend denies network during execution.' }, newProcesses: [], baselineFilesystemChanges: compareTree(initialBaseline, fileTree(baselineDir)), candidateFilesystemChanges: compareTree(initialCandidate, fileTree(candidateDir)), filesystemDifference: compareTree(fileTree(baselineDir), fileTree(candidateDir)), baselineDurationMs: baseline.reduce((n, r) => n + (r.durationMs || 0), 0), candidateDurationMs: candidate.reduce((n, r) => n + (r.durationMs || 0), 0) };
    return buildEvidence({ project, spec, metadata, packageDelta, baseline, candidate, behavior, sandbox: { backend: unsafe ? 'unsafe-host' : check.backend, unsafeHostExecution: unsafe } });
  } finally { await rm(root, { recursive: true, force: true }); }
}
function updateCandidate(dir, name, version) { const file = path.join(dir, 'package.json'); const manifest = readJson(file); let found = false; for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) if (manifest[field]?.[name] !== undefined) { manifest[field][name] = version; found = true; } if (!found) throw new Error(`${name} is not declared in package.json; DepGuard only verifies current direct dependencies in 0.1.0.`); fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`); }
function commandPlan(project, config, options) { const detected = []; const scripts = project.manifest.scripts || {}; if (!options.skipInstall) detected.push({ label: 'install', command: project.manager === 'pnpm' ? 'pnpm install --frozen-lockfile --ignore-scripts' : project.manager === 'yarn' ? 'yarn install --ignore-scripts --frozen-lockfile' : 'npm ci --ignore-scripts --no-audit --no-fund' }); for (const name of ['build', 'test', 'typecheck', 'lint']) { const command = config.commands[name] || (scripts[name] ? `${project.manager} run ${name}` : null); if (command) detected.push({ label: name, command }); } return detected; }
async function execute(commands, cwd, exec) { const results = []; for (const item of commands) { const start = performance.now(); const result = await exec(item.command, { cwd, label: item.label }); result.durationMs = Math.round(performance.now() - start); results.push(result); } return results; }
function emptyBehavior() { return { observerVersion: 'portable-v1', network: { status: 'not-run' }, newProcesses: [], baselineFilesystemChanges: [], candidateFilesystemChanges: [], filesystemDifference: [], baselineDurationMs: 0, candidateDurationMs: 0 }; }
function buildEvidence({ project, spec, metadata, packageDelta, baseline, candidate, behavior, environmentFailure, sandbox }) {
  const result = { schemaVersion: '1', predicateType: 'https://depguard.dev/attestation/compatibility/v1', ecosystem: 'npm', package: spec.name, fromVersion: metadata.from.version, toVersion: spec.toVersion, project: { anonymousProjectId: sha256(path.resolve(project.root)).slice(0, 31), lockfileDigest: project.lockPath ? sha256(fs.readFileSync(project.lockPath)) : null }, environment: { os: process.platform, arch: process.arch, runtime: { name: 'node', version: process.version }, sandbox }, supplyChain: { source: metadata.source, metadataWarning: metadata.warning, packageDelta, provenance: metadata.to.provenance, knownVulnerabilities: { status: 'not-checked', reason: 'OSV provider is pluggable but not bundled in the offline MVP.' } }, verification: { baseline, candidate, install: statusFor(candidate, 'install'), build: statusFor(candidate, 'build'), test: testCount(candidate), typecheck: statusFor(candidate, 'typecheck'), lint: statusFor(candidate, 'lint') }, behavior, privacy: { sourceUploaded: false, publishEvidence: false, rawLogsRedacted: true }, tool: { name: 'depguard', version: '0.1.0' }, timestamp: new Date().toISOString() };
  result.outcome = outcome({ baseline, candidate, packageDelta, environmentFailure }); result.id = evidenceId({ ...result, timestamp: undefined }); result.artifacts = { baselineDigest: digest(JSON.stringify(baseline)), candidateDigest: digest(JSON.stringify(candidate)), behaviorDigest: digest(JSON.stringify(behavior)) }; return result;
}
