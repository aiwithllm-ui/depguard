const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

module.exports = function () {
  const directory = process.env.DEPGUARD_OBSERVATION_DIR || '/tmp';
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(`${directory}/candidate-marker`, 'candidate\n');
  const forbiddenEnvironment = [
    'AWS_SECRET_ACCESS_KEY', 'NPM_TOKEN', 'DATABASE_URL', 'GITHUB_TOKEN'
  ].filter((name) => process.env[name] !== undefined);
  const forbiddenPaths = ['/root/.ssh', '/root/.aws', '/root/.npmrc', '/var/run/docker.sock']
    .filter((path) => fs.existsSync(path));
  fs.writeFileSync(`${directory}/sandbox-identity.json`, JSON.stringify({
    uid: typeof process.getuid === 'function' ? process.getuid() : null,
    gid: typeof process.getgid === 'function' ? process.getgid() : null,
    forbiddenEnvironment,
    forbiddenPaths,
    home: os.homedir()
  }));
  if (process.getuid() !== 0 && process.getgid() !== 0 && forbiddenEnvironment.length === 0 && forbiddenPaths.length === 0 && os.homedir() === '/home/depguard') {
    fs.writeFileSync(`${directory}/sandbox-nonroot-and-secrets-isolated`, 'verified\n');
  }
  // Deliberately harmless, but long enough for Docker process polling to observe.
  spawnSync(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 250)'], { stdio: 'ignore' });
  const networkAttempt = `const fs=require('fs'),net=require('net');const p=process.env.DEPGUARD_OBSERVATION_DIR+'/network-denied';const s=net.connect({host:'1.1.1.1',port:443});s.on('error',()=>{fs.writeFileSync(p,'denied\\n');process.exit(0)});setTimeout(()=>process.exit(2),1000)`;
  spawnSync(process.execPath, ['-e', networkAttempt], { stdio: 'ignore' });
  return 'candidate';
};
