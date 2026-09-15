import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

async function loadChallengeModule() {
  const source = await readFile(
    new URL('../src/crypto/flashChallenge.ts', import.meta.url),
    'utf8',
  );
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext },
  });
  return import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
}

test('rolling-shutter derivation matches the Rust fixed vector', async () => {
  const { deriveRollingShutterSymbols, isValidRollingShutterSequence } =
    await loadChallengeModule();
  const symbols = await deriveRollingShutterSymbols(
    new Uint8Array(32).fill(0x11),
    new Uint8Array(32).fill(0xa5),
  );
  assert.deepEqual(symbols, [2, 1, 3, 0, 3, 2, 1, 3, 1, 2, 1, 0]);
  assert.equal(isValidRollingShutterSequence(symbols), true);
});

test('rolling-shutter grammar rejects periodic and duplicate-window sequences', async () => {
  const { isValidRollingShutterSequence } = await loadChallengeModule();
  assert.equal(
    isValidRollingShutterSequence([0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3]),
    false,
  );
  assert.equal(
    isValidRollingShutterSequence([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2]),
    false,
  );
});

test('verification UI does not claim a temporal check when it was disabled', async () => {
  const source = (await readFile(
    new URL('../src/screens/verification.ts', import.meta.url),
    'utf8',
  )).replace(/^import .*;$/gm, '');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext },
  });
  const { renderVerificationScreen } = await import(
    `data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`
  );
  const result = {
    valid: true,
    verification_time_ms: 1,
    details: {
      commitment_valid: true,
      distance_check_passed: true,
      temporal_check_passed: null,
      quality_check_passed: true,
      liveness_check_passed: true,
      liveness_proved_in_zk: true,
    },
  };
  const html = renderVerificationScreen(null, false, result, null, null);
  assert.equal(html.includes('Temporal Check'), false);
  result.details.temporal_check_passed = true;
  assert.equal(
    renderVerificationScreen(null, false, result, null, null).includes('Temporal Check'),
    true,
  );
});
