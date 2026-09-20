function mark(status) { return status === 'passed' ? '✓' : status === 'failed' ? '✗' : '—'; }
function section(title, body) { return `\n${title}\n${'─'.repeat(24)}\n${body}`; }
export function renderReport(value) {
  if (value.kind === 'scan') return `DepGuard Scan${section('Project', `Package manager: ${value.project.packageManager}\nLockfile: ${value.project.lockfile || 'not found'}\nDependencies: ${value.dependencies.length}`)}\n`;
  if (value.kind === 'doctor') return `DepGuard Doctor${section('Environment', value.checks.map((c) => `${mark(c.status)} ${c.name}: ${c.detail}`).join('\n'))}\n`;
  const d = value.supplyChain.packageDelta; const b = value.behavior;
  const verification = ['install', 'build', 'test', 'typecheck', 'lint'].map((name) => `${mark(typeof value.verification[name] === 'object' ? value.verification[name].status : value.verification[name])} ${name}: ${typeof value.verification[name] === 'object' ? value.verification[name].status : value.verification[name]}`).join('\n');
  const findings = [
    ...d.lifecycleScripts.added.map((x) => `HIGH  New lifecycle script: ${x}`),
    ...(d.license.changed ? [`MEDIUM  License changed: ${d.license.before || 'unknown'} → ${d.license.after || 'unknown'}`] : []),
    ...(d.dependencies.added.length ? [`INFO  Dependency graph direct entries: ${d.dependencies.before} → ${d.dependencies.after}`] : []),
    ...(value.supplyChain.metadataWarning ? [`INFO  ${value.supplyChain.metadataWarning}`] : []),
  ];
  return `DepGuard Verification${section('Project', `Package manager: ${value.project.lockfileDigest ? 'lockfile detected' : 'no lockfile'}\nPlatform: ${value.environment.os}/${value.environment.arch}\nSandbox: ${value.environment.sandbox.backend || 'unavailable'}${value.environment.sandbox.unsafeHostExecution ? ' (UNSAFE HOST EXECUTION)' : ''}`)}${section('Candidate', `${value.package}\n${value.fromVersion} → ${value.toVersion}`)}${section('Supply-chain evidence', `${d.metadataAvailable ? '✓' : '—'} package metadata ${d.metadataAvailable ? 'compared' : 'unavailable'}\n${d.lifecycleScripts.added.length ? '!' : '✓'} lifecycle scripts ${d.lifecycleScripts.added.length ? `added: ${d.lifecycleScripts.added.join(', ')}` : 'unchanged'}\n${d.license.changed ? '!' : '✓'} license ${d.license.changed ? `${d.license.before || 'unknown'} → ${d.license.after || 'unknown'}` : 'unchanged'}`)}${section('Compatibility', verification)}${section('Behavior observation', `Network: ${b.network.status}${b.network.reason ? ` (${b.network.reason})` : ''}\nFilesystem differences: ${b.filesystemDifference.length}\nBaseline duration: ${b.baselineDurationMs} ms\nCandidate duration: ${b.candidateDurationMs} ms`)}${findings.length ? section('Findings', findings.join('\n')) : ''}${section('Outcome', `${value.outcome.code}\n${value.outcome.rationale}`)}\n`;
}
