// Flash Challenge Protocol — deterministic color pattern derivation for liveness detection.
//
// Derives a FlashPattern of 3 rounds (each with 4 quadrant RGB colors and a
// per-round grid offset) from client and server nonces using HKDF-SHA256.
// The construction is deterministic and designed to be bit-for-bit identical
// to the Rust implementation in flash_challenge.rs.
//
// HKDF-SHA256 Construction:
//   IKM:    c_nonce || s_nonce (64 bytes)
//   Salt:   "sable-flash-challenge-v1" (fixed, public)
//   Info:   "flash-colors" (fixed, public)
//   Output: 42 bytes (12 colors × 3 bytes + 3 rounds × 2 offset bytes)

// ---------------------------------------------------------------------------
// Constants (must match Rust)
// ---------------------------------------------------------------------------

const HKDF_SALT = 'sable-flash-challenge-v1';
const HKDF_INFO = 'flash-colors';
const HKDF_OUTPUT_LEN = 42;

const TEMPORAL_HKDF_SALT = 'sable-rolling-shutter-v1';
const TEMPORAL_HKDF_INFO = 'temporal-symbols';
const TEMPORAL_HKDF_OUTPUT_LEN = 4080;
export const TEMPORAL_SYMBOL_COUNT = 12;

/** Maximum red channel value when green + blue are below the low threshold. */
const RED_CAP = 204;

/** Threshold for "low" green + blue sum: G + B < 102. */
const GB_LOW_THRESHOLD = 102;

/** Minimum angular distance in degrees between paired colors. */
const MIN_ANGULAR_DISTANCE_DEG = 60.0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FlashRound {
  tlColor: [number, number, number];  // top-left RGB
  trColor: [number, number, number];  // top-right RGB
  blColor: [number, number, number];  // bottom-left RGB
  brColor: [number, number, number];  // bottom-right RGB
  offsetX: number;  // [0, 1) grid offset
  offsetY: number;  // [0, 1) grid offset
}

export interface FlashPattern {
  rounds: FlashRound[];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Derive a deterministic FlashPattern from client and server nonces using
 * HKDF-SHA256. Must produce bit-for-bit identical output to the Rust server.
 *
 * Returns 3 rounds, each with 4 quadrant colors and per-round grid offset.
 */
export async function deriveFlashPattern(
  cNonce: Uint8Array,
  sNonce: Uint8Array
): Promise<FlashRound[]> {
  // 1. Build IKM = cNonce || sNonce
  const ikm = new Uint8Array(64);
  ikm.set(cNonce, 0);
  ikm.set(sNonce, 32);

  // 2. HKDF-SHA256 extract + expand (42 bytes needs 2 HMAC blocks)
  const salt = new TextEncoder().encode(HKDF_SALT);
  const info = new TextEncoder().encode(HKDF_INFO);
  const okm = await hkdfSha256(salt, ikm, info, HKDF_OUTPUT_LEN);

  // 3. Map bytes 0..36 → 12 colors (4 per round × 3 rounds)
  const colors: Array<[number, number, number]> = [];
  for (let i = 0; i < 12; i++) {
    const offset = i * 3;
    colors.push(mapBytesToSaturatedColor(okm[offset], okm[offset + 1], okm[offset + 2]));
  }

  // 4. Apply photosensitive safety clamping
  for (let i = 0; i < colors.length; i++) {
    colors[i] = applyPhotosensitiveClamp(colors[i]);
  }

  // 5. Map bytes 36..42 → 3 × (offsetX, offsetY) as byte / 256.0
  const offsets: Array<[number, number]> = [];
  for (let i = 0; i < 3; i++) {
    offsets.push([okm[36 + i * 2] / 256.0, okm[36 + i * 2 + 1] / 256.0]);
  }

  // 6. Ensure adjacent quadrant pairs per round are visually distinct
  //    Adjacent pairs: TL-TR, TL-BL, TR-BR, BL-BR
  const rounds: FlashRound[] = [];
  for (let i = 0; i < 3; i++) {
    const base = i * 4;
    const quad: Array<[number, number, number]> = [
      colors[base], colors[base + 1], colors[base + 2], colors[base + 3],
    ];

    // Each vertex has exactly 2 neighbors in the 2×2 grid.
    // When fixing a vertex, find a color distinct from ALL its neighbors.
    const neighborMap: Array<[number, number]> = [[1, 2], [0, 3], [0, 3], [1, 2]];
    for (let pass = 0; pass < 4; pass++) {
      let allOk = true;
      for (let v = 0; v < 4; v++) {
        const [n0, n1] = neighborMap[v];
        const hasViolation =
          angularDistanceDeg(quad[v], quad[n0]) < MIN_ANGULAR_DISTANCE_DEG ||
          angularDistanceDeg(quad[v], quad[n1]) < MIN_ANGULAR_DISTANCE_DEG;
        if (hasViolation) {
          quad[v] = makeDistinctFromAll(quad[v], [quad[n0], quad[n1]]);
          quad[v] = applyPhotosensitiveClamp(quad[v]);
          allOk = false;
        }
      }
      if (allOk) break;
    }

    rounds.push({
      tlColor: quad[0],
      trColor: quad[1],
      blColor: quad[2],
      brColor: quad[3],
      offsetX: offsets[i][0],
      offsetY: offsets[i][1],
    });
  }

  return rounds;
}

/**
 * Derive the 12-symbol rolling-shutter waveform from the same joint nonce.
 * Symbols are 0=red, 1=green, 2=blue, and 3=white. The mapping and rejection
 * sampling are byte-for-byte compatible with the Rust core implementation.
 */
export async function deriveRollingShutterSymbols(
  cNonce: Uint8Array,
  sNonce: Uint8Array
): Promise<number[]> {
  if (cNonce.length !== 32 || sNonce.length !== 32) {
    throw new Error('rolling-shutter nonces must each contain 32 bytes');
  }
  const ikm = new Uint8Array(64);
  ikm.set(cNonce, 0);
  ikm.set(sNonce, 32);
  const okm = await hkdfSha256(
    new TextEncoder().encode(TEMPORAL_HKDF_SALT),
    ikm,
    new TextEncoder().encode(TEMPORAL_HKDF_INFO),
    TEMPORAL_HKDF_OUTPUT_LEN
  );

  let cursor = 0;
  while (cursor < okm.length) {
    const candidate = new Array<number>(TEMPORAL_SYMBOL_COUNT);
    candidate[0] = okm[cursor++] % 4;
    let complete = true;
    for (let i = 1; i < TEMPORAL_SYMBOL_COUNT; i++) {
      let rank = 0;
      for (;;) {
        if (cursor >= okm.length) {
          complete = false;
          break;
        }
        const byte = okm[cursor++];
        if (byte < 255) {
          rank = byte % 3;
          break;
        }
      }
      if (!complete) break;
      const previous = candidate[i - 1];
      candidate[i] = rank >= previous ? rank + 1 : rank;
    }
    if (complete && isValidRollingShutterSequence(candidate)) return candidate;
  }
  throw new Error('HKDF expansion contained no valid rolling-shutter waveform');
}

export function isValidRollingShutterSequence(symbols: readonly number[]): boolean {
  if (symbols.length !== TEMPORAL_SYMBOL_COUNT) return false;
  for (let i = 0; i < symbols.length; i++) {
    if (!Number.isInteger(symbols[i]) || symbols[i] < 0 || symbols[i] > 3) return false;
    if (symbols[i] === symbols[(i + 1) % symbols.length]) return false;
  }
  for (let shift = 1; shift < symbols.length; shift++) {
    if (symbols.every((symbol, i) => symbol === symbols[(i + shift) % symbols.length])) {
      return false;
    }
  }
  const windows = new Set<number>();
  for (let start = 0; start < symbols.length; start++) {
    let packed = 0;
    for (let offset = 0; offset < 4; offset++) {
      packed |= symbols[(start + offset) % symbols.length] << (2 * offset);
    }
    if (windows.has(packed)) return false;
    windows.add(packed);
  }
  return true;
}

/**
 * Compute a SHA-256 commitment to a client nonce.
 * Returns a hex-encoded SHA-256 hash string.
 */
export async function computeClientCommitment(
  cNonce: Uint8Array
): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', toArrayBuffer(cNonce));
  return bufferToHex(new Uint8Array(hashBuffer));
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

/** Convert a Uint8Array to a lowercase hex string. */
export function bufferToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Parse a hex string into a Uint8Array. */
export function hexToBuffer(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 using SubtleCrypto
// ---------------------------------------------------------------------------

/**
 * Convert a Uint8Array to an ArrayBuffer for SubtleCrypto compatibility.
 * SubtleCrypto's BufferSource requires ArrayBuffer (not SharedArrayBuffer).
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * HKDF-SHA256 extract + expand using SubtleCrypto HMAC primitives.
 *
 * Extract: PRK = HMAC-SHA256(salt, IKM)
 * Expand:  T(1) = HMAC-SHA256(PRK, info || 0x01)
 *          T(2) = HMAC-SHA256(PRK, T(1) || info || 0x02)
 *          ...
 *          OKM  = T(1) || T(2) || ... truncated to `length` bytes
 *
 * Supports multi-block expansion per RFC 5869.
 */
async function hkdfSha256(
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const hashLen = 32; // SHA-256 output length
  const numBlocks = Math.ceil(length / hashLen);
  if (numBlocks > 255) {
    throw new Error('HKDF output length too large');
  }

  // Extract: PRK = HMAC-SHA256(salt, IKM)
  const extractKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(salt),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const prkBuffer = await crypto.subtle.sign('HMAC', extractKey, toArrayBuffer(ikm));
  const prk = new Uint8Array(prkBuffer);

  // Expand: multi-block
  const expandKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(prk),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const okm = new Uint8Array(numBlocks * hashLen);
  let previousT = new Uint8Array(0);

  for (let i = 1; i <= numBlocks; i++) {
    // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    const expandInput = new Uint8Array(previousT.length + info.length + 1);
    expandInput.set(previousT, 0);
    expandInput.set(info, previousT.length);
    expandInput[previousT.length + info.length] = i;

    const tBuffer = await crypto.subtle.sign('HMAC', expandKey, toArrayBuffer(expandInput));
    const t = new Uint8Array(tBuffer);
    okm.set(t, (i - 1) * hashLen);
    previousT = t;
  }

  return okm.slice(0, length);
}

// ---------------------------------------------------------------------------
// Saturation mapping (must match Rust exactly)
// ---------------------------------------------------------------------------

/**
 * Map 3 raw bytes to a saturated RGB color.
 *
 * Exactly mirrors the Rust `map_bytes_to_saturated_color` function:
 * - b0 % 6 selects channel ordering (dominant, middle, weak)
 * - dominant = 180 + Math.trunc(b1 * 75 / 255)  (capped at 255)
 * - weak = Math.trunc(b2 * 75 / 255)
 * - middle = b1 ^ b2
 */
function mapBytesToSaturatedColor(
  b0: number,
  b1: number,
  b2: number
): [number, number, number] {
  const ordering = b0 % 6;

  // Rust: 180u8.saturating_add((b1 as u16 * 75 / 255) as u8)
  // Integer division truncates toward zero in Rust. In JS, Math.trunc matches.
  const dominantAdd = Math.trunc((b1 * 75) / 255);
  const dominant = Math.min(180 + dominantAdd, 255);

  // Rust: (b2 as u16 * 75 / 255) as u8
  const weak = Math.trunc((b2 * 75) / 255);

  // Rust: b1 ^ b2
  const middle = b1 ^ b2;

  switch (ordering) {
    case 0: return [dominant, middle, weak];     // R dominant, B weak
    case 1: return [dominant, weak, middle];     // R dominant, G weak
    case 2: return [middle, dominant, weak];     // G dominant, B weak
    case 3: return [weak, dominant, middle];     // G dominant, R weak
    case 4: return [middle, weak, dominant];     // B dominant, R middle
    default: return [weak, middle, dominant];    // B dominant, R weak
  }
}

/**
 * Apply WCAG 2.3.1 photosensitive safety clamping.
 *
 * If G + B < 102 and R > 204, cap R at 204.
 */
function applyPhotosensitiveClamp(
  color: [number, number, number]
): [number, number, number] {
  const [r, g, b] = color;
  const gbSum = g + b;
  if (gbSum < GB_LOW_THRESHOLD && r > RED_CAP) {
    return [RED_CAP, g, b];
  }
  return [r, g, b];
}

// ---------------------------------------------------------------------------
// Angular distance & distinctness (must match Rust exactly)
// ---------------------------------------------------------------------------

/**
 * Compute the angular distance in degrees between two RGB colors
 * treated as 3D vectors.
 */
function angularDistanceDeg(
  a: [number, number, number],
  b: [number, number, number]
): number {
  const dot = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  const magA = Math.sqrt(a[0] * a[0] + a[1] * a[1] + a[2] * a[2]);
  const magB = Math.sqrt(b[0] * b[0] + b[1] * b[1] + b[2] * b[2]);

  if (magA < Number.EPSILON || magB < Number.EPSILON) {
    return 0.0;
  }

  const cosTheta = Math.max(-1.0, Math.min(1.0, dot / (magA * magB)));
  return Math.acos(cosTheta) * (180.0 / Math.PI);
}

/**
 * Find a replacement color for `candidate` that is at least MIN_ANGULAR_DISTANCE_DEG
 * away from ALL colors in `neighbors`.  Mirrors the Rust `make_distinct_from_all`.
 */
function makeDistinctFromAll(
  candidate: [number, number, number],
  neighbors: Array<[number, number, number]>
): [number, number, number] {
  const allDistinct = (c: [number, number, number]): boolean =>
    neighbors.every(n => angularDistanceDeg(n, c) >= MIN_ANGULAR_DISTANCE_DEG);

  const transforms: Array<[number, number, number]> = [
    [candidate[2], candidate[0], candidate[1]],
    [candidate[1], candidate[2], candidate[0]],
    [(~candidate[0]) & 0xFF, (~candidate[1]) & 0xFF, (~candidate[2]) & 0xFF],
    [candidate[0] ^ 0xAA, candidate[1] ^ 0x55, candidate[2] ^ 0xAA],
  ];

  for (const c of transforms) {
    if (allDistinct(c)) {
      return c;
    }
  }

  // Edge/primary fallback: pick the color with the greatest minimum distance
  // to any neighbor.
  const edgeColors: Array<[number, number, number]> = [
    [255, 0, 0], [0, 255, 0], [0, 0, 255],
    [255, 255, 0], [0, 255, 255], [255, 0, 255],
  ];

  let bestColor = edgeColors[0];
  let bestMinDist = Math.min(...neighbors.map(n => angularDistanceDeg(n, edgeColors[0])));

  for (let i = 1; i < edgeColors.length; i++) {
    const minDist = Math.min(...neighbors.map(n => angularDistanceDeg(n, edgeColors[i])));
    if (minDist > bestMinDist) {
      bestMinDist = minDist;
      bestColor = edgeColors[i];
    }
  }

  return bestColor;
}

// ---------------------------------------------------------------------------
// Delta Fingerprint Quantization (must match Rust exactly)
// ---------------------------------------------------------------------------
//
// Encodes an RGB delta vector (or expected color) as a 16-bit fingerprint
// suitable for Hamming distance comparison inside a ZK circuit.
//
// Bit layout: [order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]
//
// Test vectors (verified against Rust):
//   [100, 0, 0]  → 24      (order=0, mid=0, min=0, mag=24)
//   [0, 200, 0]  → 16415   (order=2, mid=0, min=0, mag=31)
//   [80, 40, 10] → 3635    (order=0, mid=7, min=1, mag=19)
//   [0, 0, 0]    → 0       (no response)

/** Maximum channel value that maps to magnitude=31 (must match Rust). */
const MAGNITUDE_SCALE = 128;

/**
 * Quantize an RGB delta vector [dR, dG, dB] to a 16-bit fingerprint.
 *
 * Must produce identical output to the Rust `quantize_delta_fingerprint`.
 */
export function quantizeDeltaFingerprint(delta: [number, number, number]): number {
  // Absolute values as integers (round to nearest for cross-platform stability)
  const absChannels: [number, number, number] = [
    Math.round(Math.abs(delta[0])),
    Math.round(Math.abs(delta[1])),
    Math.round(Math.abs(delta[2])),
  ];

  // Sort descending by value; on ties, prefer lower channel index (stable)
  const indexed: Array<[number, number]> = [
    [absChannels[0], 0],
    [absChannels[1], 1],
    [absChannels[2], 2],
  ];
  indexed.sort((a, b) => {
    if (b[0] !== a[0]) return b[0] - a[0]; // descending by value
    return a[1] - b[1]; // ascending by index (stable tie-break)
  });

  const maxVal = indexed[0][0];
  const midVal = indexed[1][0];
  const minVal = indexed[2][0];
  const maxIdx = indexed[0][1];
  const midIdx = indexed[1][1];

  if (maxVal === 0) {
    return 0; // No flash response
  }

  // Channel ordering: 6 permutations of (R=0, G=1, B=2) by dominance
  let order: number;
  if (maxIdx === 0 && midIdx === 1) order = 0;      // R >= G >= B
  else if (maxIdx === 0 && midIdx === 2) order = 1;  // R >= B >= G
  else if (maxIdx === 1 && midIdx === 0) order = 2;  // G >= R >= B
  else if (maxIdx === 1 && midIdx === 2) order = 3;  // G >= B >= R
  else if (maxIdx === 2 && midIdx === 0) order = 4;  // B >= R >= G
  else order = 5;                                     // B >= G >= R

  // Ratios: mid/max and min/max, quantized to [0, 15] (integer division)
  const midRatio = Math.min(15, Math.trunc((midVal * 15) / maxVal));
  const minRatio = Math.min(15, Math.trunc((minVal * 15) / maxVal));

  // Magnitude: max channel scaled to [0, 31]
  const magnitude = Math.min(31, Math.trunc((maxVal * 31) / MAGNITUDE_SCALE));

  // Pack: [order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]
  return (order << 13) | (midRatio << 9) | (minRatio << 5) | magnitude;
}

/**
 * Quantize an expected flash color to the same fingerprint space as deltas.
 */
export function quantizeExpectedColor(color: [number, number, number]): number {
  return quantizeDeltaFingerprint(color);
}
