import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

test('credential is required for operations, omitted from health, and cleared on restart', async (t) => {
  const oldWindow = globalThis.window;
  const oldFetch = globalThis.fetch;
  t.after(() => { globalThis.window = oldWindow; globalThis.fetch = oldFetch; });
  globalThis.window = { location: { href: 'https://demo.example/' } };
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, json: async () => ({}) };
  };
  const source = (await readFile(new URL('../src/api.ts', import.meta.url), 'utf8'))
    .replace("import.meta.env.VITE_API_URL || '/api'", "'/api'");
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext },
  });
  const { api, setCredential, clearCredential } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
  await assert.rejects(api.enroll({ user_id: 'test' }), /credential is required/);
  assert.equal(calls.length, 0);
  assert.throws(() => setCredential('short'), /64-character/);
  setCredential('ab'.repeat(32));
  await api.enroll({ user_id: 'test' });
  assert.equal(calls[0].options.headers.Authorization, `Bearer ${'ab'.repeat(32)}`);
  assert.equal(calls[0].options.redirect, 'error');
  await api.health();
  assert.equal(calls[1].options.headers.Authorization, undefined);
  clearCredential();
  await assert.rejects(api.getChallenge({ session_id: 'test' }), /credential is required/);
  assert.equal(calls.length, 2);
  globalThis.window.location.href = 'http://unsafe.example/';
  assert.throws(() => setCredential('ab'.repeat(32)), /HTTPS/);
});
