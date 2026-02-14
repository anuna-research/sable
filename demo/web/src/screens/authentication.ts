import { ChallengeResponse, ProveResponse } from '../api';
import {
  CapturedFace,
  renderWebcamPreview,
  renderWebcamControls,
  initWebcam,
  captureFrame,
  stopWebcam,
} from '../components/webcam';

export type AuthPhase = 'ready' | 'challenge' | 'capturing' | 'liveness' | 'proving' | 'complete';

export function renderAuthenticationScreen(
  phase: AuthPhase,
  isLoading: boolean,
  challenge: ChallengeResponse | null,
  capturedFace: CapturedFace | null,
  proof: ProveResponse | null,
  error: string | null,
  webcamError: string | null
): string {
  const phaseLabels: Record<AuthPhase, string> = {
    ready: 'Ready to Authenticate',
    challenge: 'Challenge Received',
    capturing: 'Capture Live Face Scan',
    liveness: 'Screen Flash Liveness Check',
    proving: 'Generating Zero-Knowledge Proof...',
    complete: 'Proof Generated',
  };

  return `
    <div class="card">
      <h2>Step 2: Authentication</h2>
      <p>
        Now we capture a live face scan and generate a zero-knowledge proof.
        The proof demonstrates that your scan matches the enrolled template without
        revealing your actual biometric data.
      </p>

      <div style="display: flex; align-items: center; gap: 0.5rem; margin: 1rem 0;">
        <span class="badge ${phase === 'complete' ? 'badge-success' : 'badge-warning'}">
          ${phaseLabels[phase]}
        </span>
      </div>

      ${renderAuthPhase(phase, isLoading, challenge, capturedFace, proof, webcamError)}

      ${error ? `
        <div class="badge badge-error" style="margin-top: 1rem; display: block; padding: 0.75rem;">
          Error: ${error}
        </div>
      ` : ''}
    </div>

    <div class="card">
      <h3>What Happens During Proof Generation?</h3>
      <ol style="padding-left: 1.5rem; color: var(--text-secondary);">
        <li style="margin-bottom: 0.75rem;">
          <strong>Challenge Request:</strong> Server provides a random nonce for freshness
        </li>
        <li style="margin-bottom: 0.75rem;">
          <strong>Live Face Scan:</strong> A new face embedding is extracted from your webcam
        </li>
        <li style="margin-bottom: 0.75rem;">
          <strong>Liveness Check:</strong> Screen flash reflectance analysis verifies a real face
          (Tang et al., NDSS 2018)
        </li>
        <li style="margin-bottom: 0.75rem;">
          <strong>Circuit Execution:</strong> The Halo2 circuit verifies:
          <ul style="margin-top: 0.5rem; margin-left: 1rem;">
            <li>Features hash to the committed value</li>
            <li>Embedding similarity is above threshold</li>
            <li>Timestamp is recent</li>
            <li>Quality score is acceptable</li>
          </ul>
        </li>
        <li style="margin-bottom: 0.75rem;">
          <strong>Proof Output:</strong> A ~2KB Halo2 proof that can be verified in milliseconds
        </li>
      </ol>
    </div>
  `;
}

function renderAuthPhase(
  phase: AuthPhase,
  isLoading: boolean,
  challenge: ChallengeResponse | null,
  capturedFace: CapturedFace | null,
  proof: ProveResponse | null,
  webcamError: string | null
): string {
  switch (phase) {
    case 'ready':
      return `
        <p style="margin-bottom: 1rem;">
          Click below to request an authentication challenge and capture a live face scan.
        </p>
        <button class="btn btn-primary" id="auth-btn" ${isLoading ? 'disabled' : ''}>
          ${isLoading ? '<span class="spinner"></span> Processing...' : 'Start Authentication'}
        </button>
      `;

    case 'challenge':
      return challenge ? `
        <div class="fade-in">
          <h3>Challenge Nonce</h3>
          <div class="code" style="font-size: 0.75rem; word-break: break-all;">
            ${challenge.nonce_hex}
          </div>
          <p style="font-size: 0.875rem; margin-top: 0.5rem;">
            The server provides a random nonce to prevent replay attacks.
          </p>
          <p style="margin-top: 1rem; color: var(--text-secondary);">
            Preparing webcam for live capture...
          </p>
        </div>
      ` : '';

    case 'capturing':
      if (webcamError) {
        return `
          <div class="webcam-error">
            <p><strong>Camera Error:</strong> ${webcamError}</p>
            <p style="margin-top: 0.5rem; font-size: 0.875rem;">
              Please ensure camera permissions are granted and try again.
            </p>
            <button class="btn btn-primary" id="retry-auth-camera-btn" style="margin-top: 1rem;">
              Retry Camera Access
            </button>
          </div>
        `;
      }

      if (capturedFace) {
        return `
          <div class="fade-in">
            <h3>Live Face Capture</h3>
            ${renderWebcamPreview(capturedFace)}
            <div class="webcam-controls">
              <button class="btn btn-secondary" id="retake-auth-btn" ${isLoading ? 'disabled' : ''}>
                Retake
              </button>
              <button class="btn btn-primary" id="prove-with-capture-btn" ${isLoading ? 'disabled' : ''}>
                ${isLoading ? '<span class="spinner"></span> Processing...' : 'Generate Proof'}
              </button>
            </div>
          </div>
        `;
      }

      return `
        <div class="fade-in">
          <h3>Live Face Capture</h3>
          <div class="webcam-loading" id="auth-webcam-loading">
            <span class="spinner"></span>
            <span class="webcam-loading-text">Initializing camera...</span>
          </div>
          <div id="auth-webcam-container" style="display: none;">
            ${renderWebcamPreview(null)}
            ${renderWebcamControls(null, isLoading)}
          </div>
        </div>
      `;

    case 'liveness':
      return `
        <div class="fade-in">
          <h3>Spatial Flash Liveness Check</h3>

          <!-- Consent notice (WCAG 2.3.1) -->
          <div id="liveness-consent" style="
            background: var(--bg-secondary, #1a1a2e);
            border: 1px solid var(--border-color, #333);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            text-align: center;
          ">
            <p style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 0.75rem;">
              Liveness check will flash quadrant colors briefly. The sequence uses a
              randomized 2&times;2 grid of colors to verify a real 3D face via reflected
              light analysis (Tang et al., NDSS 2018).
            </p>
            <button class="btn btn-primary" id="liveness-consent-btn" style="font-size: 0.875rem;">
              OK, Start Liveness Check
            </button>
          </div>

          <!-- Face positioning guide (shown after consent) -->
          <div id="liveness-guide" style="display: none; text-align: center; margin: 1.5rem 0;">
            <div style="position: relative; display: inline-block;">
              <video id="liveness-video" autoplay playsinline muted
                style="width: 280px; height: 210px; border-radius: 8px; object-fit: cover;"></video>
              <!-- Oval face guide overlay -->
              <div style="
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 140px;
                height: 180px;
                border: 2px dashed rgba(255, 255, 255, 0.6);
                border-radius: 50%;
                pointer-events: none;
              "></div>
            </div>
            <p style="font-size: 0.875rem; margin-top: 0.75rem; color: var(--text-secondary);">
              Center your face in the oval, hold still
            </p>
          </div>

          <!-- Progress indicator -->
          <div id="liveness-progress" style="display: none; text-align: center; margin: 1rem 0;">
            <div style="display: flex; justify-content: center; gap: 0.75rem; margin-bottom: 0.5rem;">
              <div id="flash-dot-0" class="flash-progress-dot" style="
                width: 12px; height: 12px; border-radius: 50%;
                border: 2px solid var(--text-secondary, #888);
                background: transparent;
                transition: background 0.3s, border-color 0.3s;
              "></div>
              <div id="flash-dot-1" class="flash-progress-dot" style="
                width: 12px; height: 12px; border-radius: 50%;
                border: 2px solid var(--text-secondary, #888);
                background: transparent;
                transition: background 0.3s, border-color 0.3s;
              "></div>
              <div id="flash-dot-2" class="flash-progress-dot" style="
                width: 12px; height: 12px; border-radius: 50%;
                border: 2px solid var(--text-secondary, #888);
                background: transparent;
                transition: background 0.3s, border-color 0.3s;
              "></div>
            </div>
            <p id="liveness-status" style="font-size: 0.875rem; margin-top: 0.5rem;">
              Preparing spatial flash...
            </p>
          </div>

          <!-- Spinner shown during processing -->
          <div id="liveness-spinner" style="display: none; text-align: center; margin: 2rem 0;">
            <span class="spinner"></span>
            <p id="liveness-processing-status" style="margin-top: 0.5rem; font-size: 0.875rem;">
              Analyzing reflectance patterns...
            </p>
          </div>
        </div>
      `;

    case 'proving':
      return `
        <div class="fade-in">
          <h3>Generating Halo2 Proof</h3>
          <div class="progress-container">
            <div class="progress-bar" id="proof-progress" style="width: 0%;"></div>
          </div>
          <p id="proof-status" style="font-size: 0.875rem; text-align: center;">
            Processing captured face scan...
          </p>
        </div>
      `;

    case 'complete':
      return proof ? `
        <div class="fade-in">
          <h3>Proof Generated Successfully</h3>

          <div class="timing-grid">
            <div class="timing-item">
              <div class="timing-value">${proof.timings.feature_scan_ms.toFixed(2)}ms</div>
              <div class="timing-label">Feature Processing</div>
            </div>
            <div class="timing-item">
              <div class="timing-value">${proof.timings.distance_calc_ms.toFixed(2)}ms</div>
              <div class="timing-label">Similarity Calc</div>
            </div>
            <div class="timing-item">
              <div class="timing-value">${proof.timings.proof_generation_ms.toFixed(0)}ms</div>
              <div class="timing-label">Proof Generation</div>
            </div>
            <div class="timing-item">
              <div class="timing-value">${proof.timings.total_ms.toFixed(0)}ms</div>
              <div class="timing-label">Total</div>
            </div>
          </div>

          <h3>Biometric Match</h3>
          <div class="progress-container">
            <div class="progress-bar" style="width: ${(1 - proof.distance) * 100}%; background: linear-gradient(90deg, var(--accent-success), var(--accent-primary));"></div>
          </div>
          <p style="font-size: 0.875rem;">
            Similarity: ${((1 - proof.distance) * 100).toFixed(1)}% (threshold: 50%) -
            <span style="color: ${proof.distance < 0.5 ? 'var(--accent-success)' : 'var(--accent-error)'};">
              ${proof.distance < 0.5 ? 'Match confirmed' : 'No match'}
            </span>
          </p>

          ${proof.liveness_passed != null ? `
            <h3>Liveness Check</h3>
            <p style="font-size: 0.875rem;">
              <span style="color: ${proof.liveness_passed ? 'var(--accent-success)' : 'var(--accent-error)'};">
                ${proof.liveness_passed ? 'Passed - real face detected via screen flash reflectance' : 'Failed - liveness check did not pass'}
              </span>
            </p>
          ` : ''}

          ${proof.color_challenge_passed != null ? `
            <h3>Spatial Flash Challenge</h3>
            <p style="font-size: 0.875rem;">
              <span style="color: ${proof.color_challenge_passed ? 'var(--accent-success)' : 'var(--accent-error)'};">
                ${proof.color_challenge_passed
                  ? 'Passed - quadrant color reflectance verified 3D face geometry'
                  : 'Failed - spatial color challenge did not pass'}
              </span>
            </p>
            ${proof.spatial_differentiation_score != null ? `
              <p style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">
                Spatial differentiation score: ${proof.spatial_differentiation_score.toFixed(3)}
              </p>
            ` : ''}
          ` : ''}

          <h3>ZK Proof (truncated)</h3>
          <div class="code" style="font-size: 0.75rem; word-break: break-all;">
            ${proof.proof_hex.substring(0, 128)}...
          </div>
          <p style="font-size: 0.875rem; margin-top: 0.5rem;">
            ~2KB Halo2 proof on BN254 curve
          </p>

          <div style="margin-top: 1.5rem;">
            <button class="btn btn-primary" id="continue-to-verify">
              Continue to Verification
            </button>
          </div>
        </div>
      ` : '';

    default:
      return '';
  }
}

export function attachAuthenticationHandlers(
  onAuth: () => void,
  onCapture: () => void,
  onRetake: () => void,
  onProve: (face: CapturedFace) => void,
  onContinue: () => void,
  onRetryCamera: () => void,
  capturedFace: CapturedFace | null,
  onLivenessConsent?: () => void
): void {
  // Start authentication
  document.getElementById('auth-btn')?.addEventListener('click', onAuth);

  // Capture button
  document.getElementById('capture-btn')?.addEventListener('click', onCapture);

  // Retake button
  document.getElementById('retake-auth-btn')?.addEventListener('click', onRetake);

  // Prove with capture button
  document.getElementById('prove-with-capture-btn')?.addEventListener('click', () => {
    if (capturedFace) {
      onProve(capturedFace);
    }
  });

  // Continue to verify
  document.getElementById('continue-to-verify')?.addEventListener('click', onContinue);

  // Retry camera
  document.getElementById('retry-auth-camera-btn')?.addEventListener('click', onRetryCamera);

  // Liveness consent
  if (onLivenessConsent) {
    document.getElementById('liveness-consent-btn')?.addEventListener('click', onLivenessConsent);
  }
}

export function updateProofProgress(percent: number, status: string): void {
  const progressBar = document.getElementById('proof-progress');
  const statusEl = document.getElementById('proof-status');

  if (progressBar) {
    progressBar.style.width = `${percent}%`;
  }
  if (statusEl) {
    statusEl.textContent = status;
  }
}

export function updateLivenessStatus(status: string): void {
  const statusEl = document.getElementById('liveness-status');
  if (statusEl) {
    statusEl.textContent = status;
  }
}

/**
 * Show the face guide and progress UI after consent is given.
 */
export function showLivenessGuide(): void {
  const consent = document.getElementById('liveness-consent');
  const guide = document.getElementById('liveness-guide');
  const progress = document.getElementById('liveness-progress');
  if (consent) consent.style.display = 'none';
  if (guide) guide.style.display = 'block';
  if (progress) progress.style.display = 'block';
}

/**
 * Hide the face guide and show the processing spinner.
 */
export function showLivenessProcessing(status: string): void {
  const guide = document.getElementById('liveness-guide');
  const progress = document.getElementById('liveness-progress');
  const spinner = document.getElementById('liveness-spinner');
  const statusEl = document.getElementById('liveness-processing-status');
  if (guide) guide.style.display = 'none';
  if (progress) progress.style.display = 'none';
  if (spinner) spinner.style.display = 'block';
  if (statusEl) statusEl.textContent = status;
}

/**
 * Update flash progress dot to filled state for a completed round.
 */
export function updateFlashDot(roundIndex: number): void {
  const dot = document.getElementById(`flash-dot-${roundIndex}`);
  if (dot) {
    dot.style.background = 'var(--accent-primary, #6366f1)';
    dot.style.borderColor = 'var(--accent-primary, #6366f1)';
  }
}

/**
 * Initialize webcam for authentication screen
 */
export async function initAuthWebcam(): Promise<void> {
  const loadingEl = document.getElementById('auth-webcam-loading');
  const containerEl = document.getElementById('auth-webcam-container');
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
 * Capture frame from webcam for auth
 */
export function captureAuthFrame(): CapturedFace | null {
  return captureFrame();
}

/**
 * Stop webcam when leaving auth screen
 */
export function stopAuthWebcam(): void {
  stopWebcam();
}
