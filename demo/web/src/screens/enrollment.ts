import { EnrollResponse, FuzzyEnrollResponse } from '../api';
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
export type EnrollmentMode = 'pedersen' | 'fuzzy';

export function renderEnrollmentScreen(
  phase: EnrollmentPhase,
  isLoading: boolean,
  capturedFace: CapturedFace | null,
  result: EnrollResponse | null,
  fuzzyResult: FuzzyEnrollResponse | null,
  error: string | null,
  webcamError: string | null,
  enrollmentMode: EnrollmentMode
): string {
  const hasResult = result || fuzzyResult;

  return `
    <div class="card">
      <h2>Step 1: Enrollment</h2>
      <p>
        During enrollment, we capture your face using the webcam and create a
        cryptographic commitment. The commitment hides your actual biometric features
        while allowing future verification.
      </p>

      ${!hasResult && phase === 'capture' ? renderModeToggle(enrollmentMode) : ''}

      ${hasResult
        ? (fuzzyResult ? renderFuzzyEnrollmentSuccess(fuzzyResult) : renderEnrollmentSuccess(result!))
        : renderEnrollmentCapture(phase, isLoading, capturedFace, webcamError)}

      ${error ? `
        <div class="badge badge-error" style="margin-top: 1rem; display: block; padding: 0.75rem;">
          Error: ${error}
        </div>
      ` : ''}
    </div>

    <div class="card">
      <h3>What Happens During Enrollment?</h3>
      ${enrollmentMode === 'fuzzy' ? renderFuzzyExplainer() : renderPedersenExplainer()}
    </div>
  `;
}

function renderModeToggle(activeMode: EnrollmentMode): string {
  return `
    <div class="mode-toggle">
      <div class="mode-option ${activeMode === 'pedersen' ? 'active' : ''}" data-mode="pedersen">
        <div class="mode-option-title">Pedersen Commitment</div>
        <div class="mode-option-desc">Standard privacy-preserving commitment. Different each enrollment.</div>
      </div>
      <div class="mode-option ${activeMode === 'fuzzy' ? 'active' : ''}" data-mode="fuzzy">
        <div class="mode-option-title">Fuzzy Commitment</div>
        <div class="mode-option-desc">Deterministic commitment from biometrics. Same person always produces the same commitment, enabling deduplication.</div>
      </div>
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
        <strong>Storage:</strong> Only the commitment is stored - your face embedding remains private
      </li>
    </ol>
  `;
}

function renderFuzzyExplainer(): string {
  return `
    <ol style="padding-left: 1.5rem; color: var(--text-secondary);">
      <li style="margin-bottom: 0.75rem;">
        <strong>Face Capture:</strong> Your face is detected and a 1024-dimensional embedding is extracted
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>Binary Quantization:</strong> Adjacent pairs are averaged to 512 features, then each is mapped to 0 or 1 by sign
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>Deterministic Encoding:</strong> An RS codeword is derived from <code class="code-inline">SHA-256(binary features)</code> and XORed with the quantized vector (code-offset sketch)
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>SHA-256 Commitment:</strong> The RS messages are hashed: <code class="code-inline">C = SHA-256(msg<sub>0</sub> || msg<sub>1</sub> || tail)</code>
      </li>
      <li style="margin-bottom: 0.75rem;">
        <strong>Storage:</strong> The commitment + public helper data (XOR delta) are stored. The same person always produces the same commitment; a future scan reproduces it via error correction.
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

      <h3>Biometric Features (first 10 of 512)</h3>
      <div class="feature-viz" id="feature-viz">
        ${result.feature_preview.map(f => {
          const height = Math.abs(f) * 15 + 5;
          return `<div class="feature-bar" style="height: ${height}px;"></div>`;
        }).join('')}
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

function renderFuzzyEnrollmentSuccess(result: FuzzyEnrollResponse): string {
  const truncatedHelper = result.helper_data_hex.length > 120
    ? result.helper_data_hex.substring(0, 120) + '...'
    : result.helper_data_hex;

  return `
    <div class="fade-in">
      <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;">
        <span class="badge badge-success">Enrolled Successfully (Fuzzy Commitment)</span>
      </div>

      <h3>Deterministic Commitment</h3>
      <div class="code" style="word-break: break-all; font-size: 0.75rem;">
        ${result.commitment_hex}
      </div>
      <p style="font-size: 0.875rem; margin-top: 0.5rem;">
        This SHA-256 hash is derived deterministically from your biometrics.
        Enrolling again will produce the same commitment. A future scan within the
        error tolerance will also reproduce it via the helper data below.
      </p>

      <h3>Helper Data</h3>
      <div class="helper-data-container">
        <div class="code" style="word-break: break-all; font-size: 0.75rem;">
          ${truncatedHelper}
        </div>
        <button class="copy-btn" id="copy-helper-data" data-full="${result.helper_data_hex}">Copy</button>
      </div>
      <p style="font-size: 0.875rem; margin-top: 0.5rem;">
        Public helper data needed for future verification. Store this alongside the commitment.
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
          <div class="timing-value">${result.timings.fuzzy_commitment_ms.toFixed(3)}ms</div>
          <div class="timing-label">Fuzzy Commitment</div>
        </div>
        <div class="timing-item">
          <div class="timing-value">${result.timings.total_ms.toFixed(2)}ms</div>
          <div class="timing-label">Total</div>
        </div>
      </div>

      <div style="margin-top: 1.5rem; display: flex; gap: 0.75rem; flex-wrap: wrap;">
        <button class="btn btn-primary" id="continue-to-auth">
          Continue to Verification
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
  capturedFace: CapturedFace | null,
  onModeChange?: (mode: EnrollmentMode) => void
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

  // Mode toggle
  if (onModeChange) {
    document.querySelectorAll('.mode-option').forEach(el => {
      el.addEventListener('click', () => {
        const mode = (el as HTMLElement).dataset.mode as EnrollmentMode;
        if (mode) onModeChange(mode);
      });
    });
  }

  // Copy helper data button
  const copyBtn = document.getElementById('copy-helper-data');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const fullData = copyBtn.dataset.full || '';
      navigator.clipboard.writeText(fullData).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
      });
    });
  }
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
