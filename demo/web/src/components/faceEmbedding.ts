// Face embedding extraction using @vladmandic/human
// Extracts face embeddings for biometric authentication

import Human from '@vladmandic/human';

// Human library configuration
const humanConfig = {
  // Use WebGL backend for best performance
  backend: 'webgl' as const,
  // Model base path - use CDN
  modelBasePath: 'https://cdn.jsdelivr.net/npm/@vladmandic/human/models/',
  // Enable only what we need for face embedding
  face: {
    enabled: true,
    detector: {
      enabled: true,
      rotation: true,       // Better accuracy with rotation detection
      maxDetected: 1,       // Only need one face
      minConfidence: 0.5,
    },
    mesh: {
      enabled: true,        // Needed for accurate embedding
    },
    iris: {
      enabled: true,        // Iris centres locate the corneal glint crops (SPEC-006 REQ-114)
    },
    description: {
      enabled: true,        // This generates the face embedding!
      minConfidence: 0.5,
    },
    emotion: {
      enabled: false,       // Not needed
    },
    antispoof: {
      enabled: true,        // Client-side antispoof indicator
    },
    liveness: {
      enabled: true,        // Client-side liveness indicator
    },
  },
  body: { enabled: false },
  hand: { enabled: false },
  object: { enabled: false },
  gesture: { enabled: false },
  segmentation: { enabled: false },
};

// Singleton Human instance
let human: Human | null = null;
let loadingPromise: Promise<void> | null = null;

// Embedding size from Human library (FaceRes model)
export const FACE_EMBEDDING_SIZE = 1024;

/**
 * Initialize Human library and load models
 */
export async function initHuman(): Promise<Human> {
  if (human) {
    return human;
  }

  if (loadingPromise) {
    await loadingPromise;
    return human!;
  }

  loadingPromise = (async () => {
    console.log('Initializing Human library...');
    human = new Human(humanConfig);

    // Load models
    await human.load();
    console.log('Human models loaded successfully');

    // Warm up the model
    await human.warmup();
    console.log('Human library ready');
  })();

  await loadingPromise;
  return human!;
}

/**
 * Check if Human is ready
 */
export function isHumanReady(): boolean {
  return human !== null;
}

/**
 * Face detection result with embedding
 */
export interface FaceDetectionResult {
  embedding: number[];      // Face embedding (1024-dim from FaceRes)
  box: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  confidence: number;       // Detection confidence
  age?: number;
  gender?: string;
  genderConfidence?: number;
}

/**
 * Detect face and extract embedding from video element
 */
export async function detectFace(
  input: HTMLVideoElement | HTMLCanvasElement
): Promise<FaceDetectionResult | null> {
  if (!human) {
    throw new Error('Human not initialized. Call initHuman() first.');
  }

  const result = await human.detect(input);

  if (!result.face || result.face.length === 0) {
    return null;
  }

  const face = result.face[0];

  // Check if we have an embedding
  if (!face.embedding || face.embedding.length === 0) {
    return null;
  }

  return {
    embedding: Array.from(face.embedding),
    box: {
      x: face.box[0],
      y: face.box[1],
      width: face.box[2],
      height: face.box[3],
    },
    confidence: face.boxScore || face.faceScore || 0,
    age: face.age,
    gender: face.gender,
    genderConfidence: face.genderScore,
  };
}

/** An iris located in image pixels. */
export interface IrisLocation {
  cx: number;
  cy: number;
  /** Mean distance from centre to the four iris boundary points. */
  radius: number;
}

export interface IrisPair {
  left: IrisLocation;
  right: IrisLocation;
}

function irisFromPoints(points: [number, number, number?][]): IrisLocation | null {
  if (!points || points.length < 5) return null;
  const [cx, cy] = points[0];
  let sum = 0;
  for (let i = 1; i < 5; i++) {
    const [x, y] = points[i];
    sum += Math.hypot(x - cx, y - cy);
  }
  const radius = sum / 4;
  if (!Number.isFinite(radius) || radius <= 0) return null;
  return { cx, cy, radius };
}

/**
 * Locate both irises in a still frame.
 *
 * Runs with result caching disabled: the flash frames are near-identical
 * stills and Human would otherwise return the previous frame's landmarks.
 */
export async function detectIrises(
  input: HTMLCanvasElement | HTMLImageElement
): Promise<IrisPair | null> {
  if (!human) {
    throw new Error('Human not initialized. Call initHuman() first.');
  }
  const result = await human.detect(input, { cacheSensitivity: 0 });
  const face = result.face?.[0];
  if (!face?.annotations) return null;
  const left = irisFromPoints(face.annotations.leftEyeIris);
  const right = irisFromPoints(face.annotations.rightEyeIris);
  if (!left || !right) return null;
  return { left, right };
}

/**
 * Calculate similarity between two face embeddings
 * Returns value between 0 and 1, where 1 is identical
 */
export function calculateSimilarity(
  embedding1: number[],
  embedding2: number[]
): number {
  if (!human) {
    throw new Error('Human not initialized');
  }
  return human.match.similarity(embedding1, embedding2);
}

/**
 * Calculate distance between two face embeddings
 * Lower distance = more similar (inverse of similarity)
 */
export function calculateDistance(
  embedding1: number[],
  embedding2: number[]
): number {
  const similarity = calculateSimilarity(embedding1, embedding2);
  // Convert similarity (0-1) to distance
  // Using 1 - similarity, so 0 distance = identical faces
  return 1 - similarity;
}

/**
 * Find best match from a list of stored embeddings
 */
export function findBestMatch(
  embedding: number[],
  storedEmbeddings: { id: string; embedding: number[] }[]
): { id: string; similarity: number } | null {
  if (!human || storedEmbeddings.length === 0) {
    return null;
  }

  const descriptors = storedEmbeddings.map(e => e.embedding);
  const result = human.match.find(embedding, descriptors);

  if (result.index < 0) {
    return null;
  }

  return {
    id: storedEmbeddings[result.index].id,
    similarity: result.similarity,
  };
}

/**
 * Draw face detection box on canvas
 */
export function drawFaceBox(
  canvas: HTMLCanvasElement,
  detection: FaceDetectionResult
): void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // Clear previous drawings
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const { box, confidence } = detection;

  // Draw bounding box
  ctx.strokeStyle = confidence > 0.7 ? '#10b981' : '#f59e0b';
  ctx.lineWidth = 3;
  ctx.strokeRect(box.x, box.y, box.width, box.height);

  // Draw confidence label
  ctx.fillStyle = ctx.strokeStyle;
  ctx.font = 'bold 14px sans-serif';
  const label = `${(confidence * 100).toFixed(0)}%`;
  ctx.fillText(label, box.x, box.y - 8);
}

/**
 * Clear face detection overlay
 */
export function clearFaceBox(canvas: HTMLCanvasElement): void {
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  }
}
