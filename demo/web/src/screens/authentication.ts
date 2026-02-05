import { ChallengeResponse, ProveResponse } from '../api';
import {
  CapturedFace,
  renderWebcamPreview,
  renderWebcamControls,
  initWebcam,
  captureFrame,
  stopWebcam,
} from '../components/webcam';

export type AuthPhase = 'ready' | 'challenge' | 'capturing' | 'proving' | 'complete';

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
          <strong>Circuit Execution:</strong> The Groth16 circuit verifies:
          <ul style="margin-top: 0.5rem; margin-left: 1rem;">
            <li>Features hash to the committed value</li>
            <li>Embedding similarity is above threshold</li>
            <li>Timestamp is recent</li>
            <li>Quality score is acceptable</li>
          </ul>
        </li>
        <li style="margin-bottom: 0.75rem;">
          <strong>Proof Output:</strong> A succinct 192-byte proof that can be verified quickly
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

    case 'proving':
      return `
        <div class="fade-in">
          <h3>Generating Groth16 Proof</h3>
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

          <h3>ZK Proof (truncated)</h3>
          <div class="code" style="font-size: 0.75rem; word-break: break-all;">
            ${proof.proof_hex.substring(0, 128)}...
          </div>
          <p style="font-size: 0.875rem; margin-top: 0.5rem;">
            192-byte Groth16 proof on BLS12-381 curve
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
  capturedFace: CapturedFace | null
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
