import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { detectProject, loadConfig, scanProject } from './project.js';
import { fetchMetadataPair, parsePackageSpec } from './metadata.js';
import { verifyTransition } from './verifier.js';
import { renderReport } from './report.js';

export const EXIT = Object.freeze({ VERIFIED: 0, REVIEW: 10, FAILED: 20, SUSPICIOUS: 30, ENVIRONMENT: 40 });

const help = `DepGuard — know what changes before a dependency enters your application.

Usage:
  depguard init
  depguard doctor
  depguard scan [--json]
  depguard verify <package@version> [--json] [--output file] [--offline]
                   [--unsafe-host-execution] [--skip-install] [--metadata-file file]
  depguard verify --all [--json]
  depguard report [--json]
  depguard version

Safety: verification uses an OCI container by default. If no Docker/Podman backend
is available, DepGuard exits 40 without executing repository or package code.
--unsafe-host-execution is an explicit, prominently reported escape hatch.
`;

function has(args, flag) { return args.includes(flag); }
function value(args, flag) { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; }
function jsonOut(value) { process.stdout.write(`${JSON.stringify(value, null, 2)}\n`); }
function writeConfig(file) {
  if (fs.existsSync(file)) throw new Error(`${file} already exists; refusing to overwrite it.`);
  fs.writeFileSync(file, `version: 1\n\nverify:\n  commands:\n    build: npm run build\n    test: npm test\n    typecheck: npm run typecheck\n    lint: npm run lint\n\nsandbox:\n  backend: oci\n  network: deny\n  memory: 4GiB\n  cpus: 2\n  timeout: 20m\n\nbehavior:\n  filesystem: true\n  processes: true\n  network: true\n  performance: true\n\nprivacy:\n  publishEvidence: false\n`, 'utf8');
}

export async function main(args, { cwd = process.cwd(), stdout = process.stdout } = {}) {
  const command = args[0] || 'help';
  if (['help', '--help', '-h'].includes(command)) { stdout.write(help); return EXIT.VERIFIED; }
  if (command === 'version' || command === '--version') { stdout.write('depguard 0.1.0\n'); return EXIT.VERIFIED; }
  if (command === 'init') { writeConfig(path.join(cwd, 'depguard.yaml')); stdout.write('Created depguard.yaml. Review the verification commands before running untrusted code.\n'); return EXIT.VERIFIED; }
  if (command === 'doctor') {
    const project = detectProject(cwd);
    const { doctor } = await import('./sandbox.js');
    const result = await doctor(project);
    if (has(args, '--json')) jsonOut(result); else stdout.write(renderReport({ kind: 'doctor', ...result }));
    return result.available ? EXIT.VERIFIED : EXIT.ENVIRONMENT;
  }
  if (command === 'scan') {
    const scan = scanProject(cwd);
    if (has(args, '--json')) jsonOut(scan); else stdout.write(renderReport({ kind: 'scan', ...scan }));
    return EXIT.VERIFIED;
  }
  if (command === 'report') {
    const reportPath = path.join(cwd, '.depguard', 'reports', 'latest.json');
    if (!fs.existsSync(reportPath)) throw new Error('No saved report. Run `depguard verify <package@version>` first.');
    const evidence = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    if (has(args, '--json')) jsonOut(evidence); else stdout.write(renderReport(evidence));
    return evidence.outcome.exitCode;
  }
  if (command !== 'verify') throw new Error(`Unknown command: ${command}\n\n${help}`);

  const subject = args[1];
  if (!subject) throw new Error('Specify a dependency, for example: depguard verify axios@1.9.1');
  if (subject === '--all') throw new Error('`verify --all` is intentionally not automatic in 0.1.0. Supply explicit transitions so expensive verification is reviewable.');
  const project = detectProject(cwd);
  const config = loadConfig(cwd);
  const spec = parsePackageSpec(subject);
  const metadata = await fetchMetadataPair(spec, project, {
    offline: has(args, '--offline'), metadataFile: value(args, '--metadata-file'),
  });
  const evidence = await verifyTransition({ project, config, spec, metadata, options: {
    unsafeHostExecution: has(args, '--unsafe-host-execution'), skipInstall: has(args, '--skip-install'),
  }});
  const output = value(args, '--output');
  const reportDir = path.join(cwd, '.depguard', 'reports');
  fs.mkdirSync(reportDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(reportDir, 'latest.json'), JSON.stringify(evidence, null, 2), { mode: 0o600 });
  if (output) fs.writeFileSync(path.resolve(cwd, output), JSON.stringify(evidence, null, 2), { mode: 0o600 });
  if (has(args, '--json')) jsonOut(evidence); else stdout.write(renderReport(evidence));
  return evidence.outcome.exitCode;
}

if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
