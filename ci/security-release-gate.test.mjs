import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('release gate refuses normal and attempted override invocations', () => {
  for (const args of [[], ['--approve'], ['--research'], ['--help']]) {
    const result = spawnSync('sh', ['ci/security-release-gate.sh', ...args], {
      cwd: root, encoding: 'utf8', env: { ...process.env, SABLE_RELEASE_APPROVED: 'true' },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SECURITY RELEASE BLOCKED/);
  }
});

test('both workspace packages explicitly prohibit registry publishing', () => {
  for (const path of ['core/Cargo.toml', 'demo/server/Cargo.toml']) {
    const packageSection = read(path).split('[package]')[1]?.split(/^\[/m)[0];
    assert.match(packageSection, /^publish\s*=\s*false\b/m, path);
  }
});

test('deployment image runs the blocking gate before compilation', () => {
  const docker = read('demo/Dockerfile');
  const copy = docker.indexOf('COPY ci/security-release-gate.sh /tmp/security-release-gate.sh');
  const gate = docker.indexOf('RUN sh /tmp/security-release-gate.sh');
  const build = docker.indexOf('RUN cargo +nightly build');
  assert.ok(copy >= 0 && gate > copy && build > gate);
  assert.match(docker, /COPY --from=builder \/app\/target\/release\/demo-server/);
});

test('current security documents do not restore withdrawn assurance claims', () => {
  for (const path of ['README.md', 'landing/index.html', 'docs/security/THREAT_MODEL.md', 'docs/specs/SECURITY-REVIEW.md']) {
    const text = read(path).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
    for (const claim of [
      /biometrics never leave the device/i,
      /fresh biometric never leaves device/i,
      /no centralized biometric storage exists/i,
      /privacy preserved: biometric data never transmitted/i,
      /APPROVE for production use/i,
      /transparent setup eliminates trusted ceremony risk/i,
      /core library is feature-complete/i,
    ]) {
      assert.doesNotMatch(text, claim, path);
    }
    assert.match(text, /(?:not approved|no production approval)/i, path);
  }
});

test('landing navigation resolves locally and no simulated proof UI remains', () => {
  const html = read('landing/index.html');
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  for (const [, id] of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.has(id), id);
  assert.doesNotMatch(html, /class="terminal-pane|data-pane=/);
  assert.match(html, /centralized biometric processing/);
  assert.match(html, /not on-device-only privacy or authenticated physical capture/);
});
