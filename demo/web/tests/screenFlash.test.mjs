import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

// Run the real capture/crop pipeline with an iris detector stub and a small DOM
// double. JPEG encoding returns a lossy stand-in; crops must use original canvases.
test('eye crops use original capture canvases, never the JPEG transport frames', async (t) => {
  const captures = [];
  const detected = [];
  const crops = [];
  const video = { videoWidth: 640, videoHeight: 480 };
  t.mock.method(globalThis, 'setTimeout', (callback) => { callback(); return 0; });
  const oldDocument = globalThis.document;
  const oldWindow = globalThis.window;
  const oldDetector = globalThis.__detectIrises;
  t.after(() => {
    globalThis.document = oldDocument;
    globalThis.window = oldWindow;
    globalThis.__detectIrises = oldDetector;
  });
  globalThis.window = { matchMedia: () => ({ matches: false }) };
  globalThis.document = {
    body: { appendChild() {} },
    createElement(tag) {
      if (tag !== 'canvas') return { style: {}, appendChild() {}, remove() {} };
      const canvas = {
        width: 0, height: 0,
        getContext: () => ({ drawImage(source, ...bounds) {
          if (source === video) {
            canvas.capture = captures.length;
            captures.push(canvas);
          } else {
            assert.ok(captures.includes(source), 'crop source must be an original capture');
            crops.push({ source, bounds, canvas });
          }
        } }),
        toDataURL: (mime) => `data:${mime};base64,lossy-transport-placeholder`,
      };
      return canvas;
    },
  };
  globalThis.__detectIrises = async (canvas) => {
    assert.ok(captures.includes(canvas));
    detected.push(canvas);
    return { left: { cx: 200, cy: 200, radius: 8 }, right: { cx: 300, cy: 200, radius: 8 } };
  };
  const source = (await readFile(new URL('../src/components/screenFlash.ts', import.meta.url), 'utf8'))
    .replace("import { detectIrises, IrisPair } from './faceEmbedding';", 'const detectIrises = globalThis.__detectIrises;');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext },
  });
  const { performSpatialFlash } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
  const round = { offsetX: 0.5, offsetY: 0.5, tlColor: [255, 0, 0], trColor: [0, 255, 0], blColor: [0, 0, 255], brColor: [255, 255, 0] };
  const result = await performSpatialFlash([round, round, round], video);
  assert.equal(captures.length, 4);
  assert.deepEqual(detected, captures);
  assert.equal(crops.length, 8);
  assert.deepEqual(crops.map(c => c.source.capture), [0, 0, 1, 1, 2, 2, 3, 3]);
  assert.equal(new Set(crops.map(c => c.canvas.width)).size, 1);
  assert.match(result.baselineDataUrl, /^data:image\/jpeg/);
  assert.equal(result.roundFrames.length, 3);
  assert.equal(result.eyeCrops.length, 4);
  for (const pair of result.eyeCrops) {
    assert.equal(pair.length, 2);
    for (const crop of pair) assert.match(crop, /^data:image\/png/);
  }
});
