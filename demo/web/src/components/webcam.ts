// Webcam capture component with face detection using Human library
// Provides webcam initialization, live preview with face detection overlay, and embedding capture

import {
  initHuman,
  isHumanReady,
  detectFace,
  drawFaceBox,
  clearFaceBox,
  FaceDetectionResult,
  FACE_EMBEDDING_SIZE,
} from './faceEmbedding';

export interface CapturedFace {
  dataUrl: string;           // Base64 data URL for display (captured frame)
  embedding: number[];       // Face embedding (1024-dim from Human)
  confidence: number;        // Detection confidence (0-1)
  box: FaceDetectionResult['box'];  // Face bounding box
}

export interface WebcamState {
  stream: MediaStream | null;
  video: HTMLVideoElement | null;
  overlay: HTMLCanvasElement | null;
  isActive: boolean;
  error: string | null;
  faceDetected: boolean;
  lastDetection: FaceDetectionResult | null;
}

let webcamState: WebcamState = {
  stream: null,
  video: null,
  overlay: null,
  isActive: false,
  error: null,
  faceDetected: false,
  lastDetection: null,
};

let detectionLoop: number | null = null;

// Target capture dimensions
const CAPTURE_WIDTH = 640;
const CAPTURE_HEIGHT = 480;

/**
 * Initialize webcam and start video stream with face detection
 */
export async function initWebcam(
  videoElement: HTMLVideoElement,
  overlayCanvas: HTMLCanvasElement
): Promise<void> {
  try {
    // Initialize Human library first (loads models)
    await initHuman();

    // Request camera access
    const stream = await navigator.mediaDevices.getUserMedia({
      video: {
        width: { ideal: CAPTURE_WIDTH },
        height: { ideal: CAPTURE_HEIGHT },
        facingMode: 'user', // Front camera for face capture
      },
      audio: false,
    });

    // Attach stream to video element
    videoElement.srcObject = stream;
    await videoElement.play();

    // Wait for video to be ready
    await new Promise<void>((resolve) => {
      if (videoElement.readyState >= 2) {
        resolve();
      } else {
        videoElement.onloadeddata = () => resolve();
      }
    });

    // Set up overlay canvas to match video dimensions
    overlayCanvas.width = videoElement.videoWidth || CAPTURE_WIDTH;
    overlayCanvas.height = videoElement.videoHeight || CAPTURE_HEIGHT;

    webcamState = {
      stream,
      video: videoElement,
      overlay: overlayCanvas,
      isActive: true,
      error: null,
      faceDetected: false,
      lastDetection: null,
    };

    // Start continuous face detection
    startFaceDetection();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Camera access denied';
    webcamState.error = message;
    throw new Error(message);
  }
}

/**
 * Start continuous face detection loop using requestAnimationFrame
 */
function startFaceDetection(): void {
  if (detectionLoop) {
    cancelAnimationFrame(detectionLoop);
  }

  let lastDetectionTime = 0;
  const detectionInterval = 150; // Run detection every 150ms (~7 FPS)

  async function detect(timestamp: number) {
    if (!webcamState.video || !webcamState.overlay || !webcamState.isActive) {
      return;
    }

    // Throttle detection to avoid overloading
    if (timestamp - lastDetectionTime >= detectionInterval) {
      lastDetectionTime = timestamp;

      try {
        const detection = await detectFace(webcamState.video);

        // Re-check state after async gap (webcam may have been stopped)
        if (!webcamState.overlay || !webcamState.isActive) return;

        if (detection) {
          webcamState.faceDetected = true;
          webcamState.lastDetection = detection;

          // Draw face box on overlay
          drawFaceBox(webcamState.overlay, detection);

          // Update UI indicator
          updateFaceIndicator(true, detection.confidence);
        } else {
          webcamState.faceDetected = false;
          webcamState.lastDetection = null;

          // Clear overlay
          clearFaceBox(webcamState.overlay);
          updateFaceIndicator(false, 0);
        }
      } catch (error) {
        if (webcamState.isActive) {
          console.error('Face detection error:', error);
        }
      }
    }

    // Continue loop
    if (webcamState.isActive) {
      detectionLoop = requestAnimationFrame(detect);
    }
  }

  detectionLoop = requestAnimationFrame(detect);
}

/**
 * Update face detection indicator in UI
 */
function updateFaceIndicator(detected: boolean, confidence: number): void {
  const indicator = document.getElementById('face-indicator');
  if (indicator) {
    if (detected) {
      indicator.className = 'face-indicator detected';
      indicator.textContent = `Face detected (${(confidence * 100).toFixed(0)}%)`;
    } else {
      indicator.className = 'face-indicator';
      indicator.textContent = 'Position your face in the frame';
    }
  }
}

/**
 * Capture current frame with face embedding
 */
export function captureFrame(): CapturedFace | null {
  if (!webcamState.video || !webcamState.isActive) {
    return null;
  }

  if (!webcamState.faceDetected || !webcamState.lastDetection) {
    return null;
  }

  const video = webcamState.video;
  const width = video.videoWidth || CAPTURE_WIDTH;
  const height = video.videoHeight || CAPTURE_HEIGHT;

  // Create canvas for capture
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;

  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return null;
  }

  // Draw current video frame (flip for mirror effect)
  ctx.translate(width, 0);
  ctx.scale(-1, 1);
  ctx.drawImage(video, 0, 0, width, height);

  // Get data URL for display
  const dataUrl = canvas.toDataURL('image/jpeg', 0.9);

  return {
    dataUrl,
    embedding: webcamState.lastDetection.embedding,
    confidence: webcamState.lastDetection.confidence,
    box: webcamState.lastDetection.box,
  };
}

/**
 * Stop webcam and release resources
 */
export function stopWebcam(): void {
  if (detectionLoop) {
    cancelAnimationFrame(detectionLoop);
    detectionLoop = null;
  }

  if (webcamState.stream) {
    webcamState.stream.getTracks().forEach(track => track.stop());
  }

  if (webcamState.video) {
    webcamState.video.srcObject = null;
  }

  if (webcamState.overlay) {
    clearFaceBox(webcamState.overlay);
  }

  webcamState = {
    stream: null,
    video: null,
    overlay: null,
    isActive: false,
    error: null,
    faceDetected: false,
    lastDetection: null,
  };
}

/**
 * Check if webcam is currently active
 */
export function isWebcamActive(): boolean {
  return webcamState.isActive;
}

/**
 * Check if face is currently detected
 */
export function isFaceDetected(): boolean {
  return webcamState.faceDetected;
}

/**
 * Get current webcam error if any
 */
export function getWebcamError(): string | null {
  return webcamState.error;
}

/**
 * Check if face models are loaded
 */
export function areFaceModelsReady(): boolean {
  return isHumanReady();
}

/**
 * Render webcam preview UI with face detection overlay
 */
export function renderWebcamPreview(capturedFace: CapturedFace | null): string {
  if (capturedFace) {
    // Show captured image preview
    return `
      <div class="webcam-container">
        <div class="captured-preview">
          <img src="${capturedFace.dataUrl}" alt="Captured face" class="captured-image" />
          <div class="capture-info">
            <span class="badge badge-success">Face Captured</span>
            <span class="capture-confidence">${(capturedFace.confidence * 100).toFixed(0)}% confidence</span>
          </div>
        </div>
      </div>
    `;
  }

  // Show live webcam preview with overlay
  return `
    <div class="webcam-container">
      <div class="webcam-preview-wrapper">
        <video id="webcam-video" class="webcam-preview" autoplay playsinline muted></video>
        <canvas id="webcam-overlay" class="webcam-overlay"></canvas>
        <div id="face-indicator" class="face-indicator">
          Loading face detection models...
        </div>
      </div>
    </div>
  `;
}

/**
 * Render webcam controls
 */
export function renderWebcamControls(
  capturedFace: CapturedFace | null,
  isLoading: boolean
): string {
  if (capturedFace) {
    return `
      <div class="webcam-controls">
        <button class="btn btn-secondary" id="retake-btn" ${isLoading ? 'disabled' : ''}>
          Retake Photo
        </button>
        <button class="btn btn-primary" id="use-capture-btn" ${isLoading ? 'disabled' : ''}>
          ${isLoading ? '<span class="spinner"></span> Processing...' : 'Use This Capture'}
        </button>
      </div>
    `;
  }

  return `
    <div class="webcam-controls">
      <button class="btn btn-primary capture-btn" id="capture-btn" ${isLoading ? 'disabled' : ''}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <circle cx="12" cy="12" r="4"/>
        </svg>
        Capture Face
      </button>
      <p class="capture-hint">Make sure your face is clearly visible and well-lit</p>
    </div>
  `;
}

// Re-export for convenience
export { FACE_EMBEDDING_SIZE };
