import { EnrollResponse } from '../api';
import {
  CapturedFace,
  renderWebcamPreview,
  renderWebcamControls,
  initWebcam,
  captureFrame,
  stopWebcam,
} from '../components/webcam';

// Enrollment phase tracking
export type EnrollmentPhase = 'capture' | 'preview' | 'success';

export function renderEnrollmentScreen(
  phase: EnrollmentPhase,
  isLoading: boolean,
  capturedFace: CapturedFace | null,
  result: EnrollResponse | null,
  error: string | null,
  webcamError: string | null
): string {
  const hasResult = result;

  return `
    <div class="card">
      <h2>Step 1: Enrollment</h2>
      <p>
        This experimental demo uploads your face embedding to the server for
        centralized biometric processing. Authentication also uploads captured
        frames and eye crops. Enrollment data is retained for up to 15 minutes,
        with expired records evicted every five seconds. Do not use sensitive
        real-world biometric data or treat a passing result as proof of identity.
      </p>


      ${hasResult
        ? renderEnrollmentSuccess(result!)
        : renderEnrollmentCapture(phase, isLoading, capturedFace, webcamError)}

      ${error ? `
        <div class="badge badge-error" style="margin-top: 1rem; display: block; padding: 0.75rem;">
          Error: ${error}
        </div>
      ` : ''}
    </div>

    <div class="card">
      <h3>What Happens During Enrollment?</h3>
      ${renderPedersenExplainer()}
    </div>
  `;
}


function renderPedersenExplainer(): string {
  return `
    <ol style="padding-left: 1.5rem; color: var(--text-secondary);">
      <li style="margin-bottom: 0.75rem;">
        <strong>Face Capture:</strong> Your face is detected and a 1024-dimensional embedding is extracted
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>Feature Conversion:</strong> The embedding is converted to 512 ZK-compatible features
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>Poseidon Hash:</strong> Features are hashed using a ZK-friendly hash function
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>Pedersen Commitment:</strong> The hash is committed using <code class="code-inline">C = g^hash &times; h^salt</code>
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>Storage:</strong> The server temporarily stores the embedding and matcher template as well as the commitments
      </li>
    </ol>
  `;
}


function renderEnrollmentCapture(
  phase: EnrollmentPhase,
  isLoading: boolean,
  capturedFace: CapturedFace | null,
  webcamError: string | null
): string {
  if (webcamError) {
    return `
      <div class="webcam-error">
        <p><strong>Camera Error:</strong> ${webcamError}</p>
        <p style="margin-top: 0.5rem; font-size: 0.875rem;">
          Please ensure camera permissions are granted and try again.
        </p>
        <button class="btn btn-primary" id="retry-camera-btn" style="margin-top: 1rem;">
          Retry Camera Access
        </button>
      </div>
    `;
  }

  if (phase === 'capture') {
    return `
      <div class="webcam-loading" id="webcam-loading">
        <span class="spinner"></span>
        <span class="webcam-loading-text">Loading face detection models...</span>
      </div>
      <div id="webcam-container" style="display: none;">
        ${renderWebcamPreview(null)}
        ${renderWebcamControls(null, isLoading)}
      </div>
    `;
  }

  // Preview phase - showing captured image
  return `
    <div class="fade-in">
      ${renderWebcamPreview(capturedFace)}
      ${renderWebcamControls(capturedFace, isLoading)}
    </div>
  `;
}

function renderEnrollmentSuccess(result: EnrollResponse): string {
  return `
    <div class="fade-in">
      <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;">
        <span class="badge badge-success">Enrolled Successfully</span>
      </div>

      <h3>Cryptographic Commitment</h3>
      <div class="code" style="word-break: break-all; font-size: 0.75rem;">
        ${result.commitment_hex}
      </div>
      <p style="font-size: 0.875rem; margin-top: 0.5rem;">
        This 48-byte commitment represents your biometrics on the BLS12-381 curve.
        It reveals nothing about your actual face.
      </p>

      <h3>Quality Score</h3>
      <div class="progress-container">
        <div class="progress-bar" style="width: ${result.quality_score * 100}%;"></div>
      </div>
      <p style="font-size: 0.875rem;">${(result.quality_score * 100).toFixed(1)}% - ${getQualityLabel(result.quality_score)}</p>

      <h3>Performance Timings</h3>
      <div class="timing-grid">
        <div class="timing-item">
          <div class="timing-value">${result.timings.feature_generation_ms.toFixed(2)}ms</div>
          <div class="timing-label">Feature Processing</div>
        </div>
        <div class="timing-item">
          <div class="timing-value">${result.timings.poseidon_hash_ms.toFixed(2)}ms</div>
          <div class="timing-label">Poseidon Hash</div>
        </div>
        <div class="timing-item">
          <div class="timing-value">${result.timings.pedersen_commit_ms.toFixed(3)}ms</div>
          <div class="timing-label">Pedersen Commit</div>
        </div>
        <div class="timing-item">
          <div class="timing-value">${result.timings.total_ms.toFixed(2)}ms</div>
          <div class="timing-label">Total</div>
        </div>
      </div>

      <div style="margin-top: 1.5rem;">
        <button class="btn btn-primary" id="continue-to-auth">
          Continue to Authentication
        </button>
      </div>
    </div>
  `;
}


function getQualityLabel(score: number): string {
  if (score >= 0.9) return 'Excellent quality';
  if (score >= 0.8) return 'Good quality';
  if (score >= 0.7) return 'Acceptable quality';
  return 'Low quality';
}

export function attachEnrollmentHandlers(
  onCapture: () => void,
  onRetake: () => void,
  onEnroll: (face: CapturedFace) => void,
  onContinue: () => void,
  onRetryCamera: () => void,
  capturedFace: CapturedFace | null
): void {
  // Capture button
  document.getElementById('capture-btn')?.addEventListener('click', onCapture);

  // Retake button
  document.getElementById('retake-btn')?.addEventListener('click', onRetake);

  // Use capture / enroll button
  document.getElementById('use-capture-btn')?.addEventListener('click', () => {
    if (capturedFace) {
      onEnroll(capturedFace);
    }
  });

  // Continue to auth button
  document.getElementById('continue-to-auth')?.addEventListener('click', onContinue);

  // Retry camera button
  document.getElementById('retry-camera-btn')?.addEventListener('click', onRetryCamera);


}

/**
 * Initialize webcam for enrollment screen
 */
export async function initEnrollmentWebcam(): Promise<void> {
  const loadingEl = document.getElementById('webcam-loading');
  const containerEl = document.getElementById('webcam-container');
  const videoEl = document.getElementById('webcam-video') as HTMLVideoElement;
  const overlayEl = document.getElementById('webcam-overlay') as HTMLCanvasElement;

  if (!videoEl || !overlayEl || !loadingEl || !containerEl) {
    return;
  }

  try {
    await initWebcam(videoEl, overlayEl);
    loadingEl.style.display = 'none';
    containerEl.style.display = 'block';
  } catch {
    throw new Error('Failed to initialize webcam');
  }
}

/**
 * Capture frame from webcam
 */
export function captureEnrollmentFrame(): CapturedFace | null {
  return captureFrame();
}

/**
 * Stop webcam when leaving enrollment
 */
export function stopEnrollmentWebcam(): void {
  stopWebcam();
}
