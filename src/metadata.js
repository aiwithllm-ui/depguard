import fs from 'node:fs';
import https from 'node:https';
import { installedVersion } from './project.js';

export function parsePackageSpec(input) {
  const at = input.lastIndexOf('@');
  if (at <= 0 || (input.startsWith('@') && at === 0)) throw new Error(`Expected exact package@version, received: ${input}`);
  return { name: input.slice(0, at), toVersion: input.slice(at + 1) };
}
function requestJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { accept: 'application/vnd.npm.install-v1+json', 'user-agent': 'depguard/0.1.0' }, timeout: 8000 }, (res) => {
      let body = ''; res.setEncoding('utf8'); res.on('data', (chunk) => { body += chunk; if (body.length > 5_000_000) req.destroy(new Error('Registry response exceeded 5 MB')); });
      res.on('end', () => { if (res.statusCode !== 200) return reject(new Error(`Registry returned HTTP ${res.statusCode}`)); try { resolve(JSON.parse(body)); } catch { reject(new Error('Registry returned invalid JSON')); } });
    });
    req.on('timeout', () => req.destroy(new Error('Registry request timed out'))); req.on('error', reject);
  });
}
function normalize(version, entry) {
  if (!entry) return { version, available: false, dependencies: {}, scripts: {}, license: null, provenance: 'unavailable' };
  return { version, available: true, dependencies: entry.dependencies || {}, optionalDependencies: entry.optionalDependencies || {}, peerDependencies: entry.peerDependencies || {}, scripts: entry.scripts || {}, license: entry.license || null, maintainers: entry.maintainers || [], dist: entry.dist || {}, repository: entry.repository || null, provenance: entry._provenance || 'not-checked' };
}
export async function fetchMetadataPair(spec, project, { offline = false, metadataFile } = {}) {
  const fromVersion = installedVersion(project, spec.name);
  if (!fromVersion) throw new Error(`Could not determine the current installed version of ${spec.name} from package.json or package-lock.json.`);
  let registry; let source = 'npm-registry'; let warning = null;
  if (metadataFile) { registry = JSON.parse(fs.readFileSync(metadataFile, 'utf8')); source = 'local-metadata-file'; }
  else if (!offline) { try { registry = await requestJson(`https://registry.npmjs.org/${encodeURIComponent(spec.name).replace('%40', '@')}`); } catch (error) { warning = `Registry metadata unavailable: ${error.message}`; } }
  else warning = 'Registry lookup disabled by --offline.';
  // A dist-tag is a selection request, not evidence. Resolve it to the exact candidate
  // before any evidence is emitted so the attestation always names a concrete version.
  if (registry?.['dist-tags']?.[spec.toVersion]) spec.toVersion = registry['dist-tags'][spec.toVersion];
  const versions = registry?.versions || {};
  return { source, warning, from: normalize(fromVersion, versions[fromVersion]), to: normalize(spec.toVersion, versions[spec.toVersion]) };
}
