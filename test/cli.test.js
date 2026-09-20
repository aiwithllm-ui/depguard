import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function verify(fixture, candidate) {
  const cwd = path.join(root, 'fixtures', fixture);
  return spawnSync(process.execPath, [path.join(root, 'bin/depguard.js'), 'verify', `example-package@${candidate}`, '--unsafe-host-execution', '--skip-install', '--offline', '--metadata-file', 'metadata.json', '--json'], { cwd, encoding: 'utf8' });
}
test('safe fixture produces independently structured verified evidence', () => {
  const result = verify('npm-safe', '1.1.0');
  assert.equal(result.status, 0, result.stderr);
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.outcome.code, 'VERIFIED AGAINST CONFIGURED CHECKS');
  assert.equal(evidence.privacy.sourceUploaded, false);
  assert.equal(evidence.verification.build, 'passed');
});
test('breaking fixture is a compatibility failure rather than a trust opinion', () => {
  const result = verify('npm-breaking-update', '2.0.0');
  assert.equal(result.status, 20, result.stderr);
  assert.equal(JSON.parse(result.stdout).outcome.code, 'VERIFICATION FAILED');
});
test('new postinstall scripts require review after configured checks pass', () => {
  const result = verify('npm-install-script', '1.1.0');
  assert.equal(result.status, 10, result.stderr);
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.outcome.code, 'REVIEW REQUIRED');
  assert.deepEqual(evidence.supplyChain.packageDelta.lifecycleScripts.added, ['postinstall']);
});
