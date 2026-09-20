#!/usr/bin/env node
// Compatibility launcher only. The Rust CLI is the authoritative verifier.
import { spawnSync } from 'node:child_process';

const result = spawnSync('cargo', ['run', '--quiet', '-p', 'depguard-cli', '--', ...process.argv.slice(2)], {
  cwd: new URL('..', import.meta.url),
  stdio: 'inherit',
});
if (result.error) {
  process.stderr.write(`DepGuard Rust core could not start: ${result.error.message}\n`);
  process.exitCode = 40;
} else {
  process.exitCode = result.status ?? 40;
}
