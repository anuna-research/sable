// Flash Challenge Protocol — deterministic color pattern derivation for liveness detection.
//
// Derives a FlashPattern of 3 rounds (each with 2 RGB colors) from client and server
// nonces using HKDF-SHA256. The construction is deterministic and designed to be
// bit-for-bit identical to the Rust implementation in flash_challenge.rs.
//
// HKDF-SHA256 Construction:
//   IKM:    c_nonce || s_nonce (64 bytes)
//   Salt:   "sable-flash-challenge-v1" (fixed, public)
//   Info:   "flash-colors" (fixed, public)
//   Output: 18 bytes (6 colors x 3 bytes each)

// ---------------------------------------------------------------------------
// Constants (must match Rust)
// ---------------------------------------------------------------------------

const HKDF_SALT = 'sable-flash-challenge-v1';
const HKDF_INFO = 'flash-colors';
const HKDF_OUTPUT_LEN = 18;

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
  topColor: [number, number, number];    // RGB tuple
  bottomColor: [number, number, number]; // RGB tuple
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
 */
export async function deriveFlashPattern(
  cNonce: Uint8Array,
  sNonce: Uint8Array
): Promise<FlashRound[]> {
  // 1. Build IKM = cNonce || sNonce
  const ikm = new Uint8Array(64);
  ikm.set(cNonce, 0);
  ikm.set(sNonce, 32);

  // 2. HKDF-SHA256 extract + expand
  const salt = new TextEncoder().encode(HKDF_SALT);
  const info = new TextEncoder().encode(HKDF_INFO);
  const okm = await hkdfSha256(salt, ikm, info, HKDF_OUTPUT_LEN);

  // 3. Map each 3-byte group to a saturated RGB color
  const colors: Array<[number, number, number]> = [];
  for (let i = 0; i < 6; i++) {
    const offset = i * 3;
    colors.push(mapBytesToSaturatedColor(okm[offset], okm[offset + 1], okm[offset + 2]));
  }

  // 4. Apply photosensitive safety clamping
  for (let i = 0; i < colors.length; i++) {
    colors[i] = applyPhotosensitiveClamp(colors[i]);
  }

  // 5. Ensure paired colors per round are visually distinct
  const rounds: FlashRound[] = [];
  for (let i = 0; i < 3; i++) {
    const top = colors[i * 2];
    let bottom = colors[i * 2 + 1];

    if (angularDistanceDeg(top, bottom) < MIN_ANGULAR_DISTANCE_DEG) {
      bottom = makeDistinct(top, bottom);
      bottom = applyPhotosensitiveClamp(bottom);
    }

    rounds.push({ topColor: top, bottomColor: bottom });
  }

  return rounds;
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
 *          Output = first `length` bytes of T(1)
 *
 * For our use case, length <= 32 so a single expand block suffices.
 */
async function hkdfSha256(
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  if (length > 32) {
    throw new Error('HKDF output length > 32 not supported in single-block expand');
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

  // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
  const expandKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(prk),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const expandInput = new Uint8Array(info.length + 1);
  expandInput.set(info, 0);
  expandInput[info.length] = 0x01;

  const t1Buffer = await crypto.subtle.sign('HMAC', expandKey, toArrayBuffer(expandInput));
  return new Uint8Array(t1Buffer).slice(0, length);
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
 * Deterministically adjust `candidate` to be visually distinct from `anchor`.
 *
 * Mirrors the Rust `make_distinct` function exactly: tries a sequence of
 * deterministic transformations until angular distance exceeds the threshold.
 */
function makeDistinct(
  anchor: [number, number, number],
  candidate: [number, number, number]
): [number, number, number] {
  const candidates: Array<[number, number, number]> = [
    // Rotation 1: R -> G, G -> B, B -> R
    [candidate[2], candidate[0], candidate[1]],
    // Rotation 2: R -> B, G -> R, B -> G
    [candidate[1], candidate[2], candidate[0]],
    // Bitwise invert (JS bitwise NOT on u8 = ~x & 0xFF for unsigned byte behavior)
    [(~candidate[0]) & 0xFF, (~candidate[1]) & 0xFF, (~candidate[2]) & 0xFF],
    // XOR with alternating pattern
    [candidate[0] ^ 0xAA, candidate[1] ^ 0x55, candidate[2] ^ 0xAA],
    // Force perpendicular: set the anchor's weakest channel to 255, zero others
    forcePerpendicularPrimary(anchor),
  ];

  for (const c of candidates) {
    if (angularDistanceDeg(anchor, c) >= MIN_ANGULAR_DISTANCE_DEG) {
      return c;
    }
  }

  // Ultimate fallback: pick the edge color furthest from anchor
  const edgeColors: Array<[number, number, number]> = [
    [255, 0, 0],     // pure R
    [0, 255, 0],     // pure G
    [0, 0, 255],     // pure B
    [255, 255, 0],   // R+G
    [0, 255, 255],   // G+B
    [255, 0, 255],   // R+B
  ];

  let bestColor = edgeColors[0];
  let bestDist = angularDistanceDeg(anchor, edgeColors[0]);

  for (let i = 1; i < edgeColors.length; i++) {
    const dist = angularDistanceDeg(anchor, edgeColors[i]);
    if (dist > bestDist) {
      bestDist = dist;
      bestColor = edgeColors[i];
    }
  }

  return bestColor;
}

/**
 * Create a pure primary-axis color based on the anchor's weakest channel.
 *
 * Mirrors the Rust `force_perpendicular_primary` function.
 */
function forcePerpendicularPrimary(
  anchor: [number, number, number]
): [number, number, number] {
  const channels = [anchor[0], anchor[1], anchor[2]];
  let minIdx = 0;
  let minVal = channels[0];
  for (let i = 1; i < 3; i++) {
    if (channels[i] < minVal) {
      minVal = channels[i];
      minIdx = i;
    }
  }

  switch (minIdx) {
    case 0: return [255, 0, 0];   // anchor weak in R -> pure R
    case 1: return [0, 255, 0];   // anchor weak in G -> pure G
    default: return [0, 0, 255];  // anchor weak in B -> pure B
  }
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
