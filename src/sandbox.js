import { spawn, spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

export async function doctor(project) {
  const docker = spawnSync('docker', ['info'], { encoding: 'utf8', timeout: 5000 });
  const podman = docker.status === 0 ? null : spawnSync('podman', ['info'], { encoding: 'utf8', timeout: 5000 });
  const backend = docker.status === 0 ? 'docker' : podman?.status === 0 ? 'podman' : null;
  return {
    backend, available: Boolean(backend), packageManager: project.manager, node: process.version,
    platform: `${process.platform}/${process.arch}`,
    checks: [
      { name: 'package manifest', status: 'passed', detail: path.basename(project.manifestPath) },
      { name: 'OCI sandbox', status: backend ? 'passed' : 'failed', detail: backend ? `${backend} daemon reachable` : 'Docker or Podman daemon was not reachable; no untrusted code can be run safely.' },
      { name: 'runtime', status: 'passed', detail: `node ${process.version}` },
    ],
  };
}

function safeEnv(home) {
  return { PATH: process.env.PATH || '', HOME: home, TMPDIR: path.join(home, 'tmp'), CI: 'true', NO_COLOR: '1', npm_config_audit: 'false', npm_config_fund: 'false' };
}
export function runHost(command, { cwd, timeoutMs = 1_200_000, label }) {
  return new Promise((resolve) => {
    const home = path.join(cwd, '.depguard-home');
    const child = spawn(command, { cwd, shell: true, env: safeEnv(home), detached: process.platform !== 'win32' });
    let stdout = ''; let stderr = ''; let killed = false;
    const timer = setTimeout(() => { killed = true; if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL'); else child.kill('SIGKILL'); }, timeoutMs);
    child.stdout.on('data', (chunk) => { stdout += chunk; }); child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ label, command, exitCode: code ?? 1, signal, timedOut: killed, stdout: redact(stdout), stderr: redact(stderr) }); });
    child.on('error', (error) => { clearTimeout(timer); resolve({ label, command, exitCode: 1, stderr: error.message, stdout: '', timedOut: false }); });
  });
}
export function runOci(command, { cwd, backend, timeoutMs = 1_200_000, label }) {
  // The source copy is the only host mount. The container has no network, no capabilities,
  // no host home, and a read-only root. OCI remains the default execution path.
  const args = ['run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=4g', '--cpus=2', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m', '-v', `${cwd}:/workspace:rw`, '-w', '/workspace', 'node:20-alpine', 'sh', '-lc', command];
  return new Promise((resolve) => {
    const child = spawn(backend, args, { env: { PATH: process.env.PATH || '' } }); let stdout = ''; let stderr = ''; let killed = false;
    const timer = setTimeout(() => { killed = true; child.kill('SIGKILL'); }, timeoutMs);
    child.stdout.on('data', (chunk) => { stdout += chunk; }); child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ label, command, exitCode: code ?? 1, signal, timedOut: killed, stdout: redact(stdout), stderr: redact(stderr) }); });
    child.on('error', (error) => { clearTimeout(timer); resolve({ label, command, exitCode: 1, stderr: error.message, stdout: '', timedOut: false }); });
  });
}
function redact(text) {
  return text.replace(/(authorization|token|password|secret|cookie)\s*[:=]\s*[^\s]+/gi, '$1=[REDACTED]').slice(-20_000);
}
