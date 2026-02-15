import {
  api,
  EnrollResponse,
  FuzzyEnrollResponse,
  FuzzyVerifyResponse,
  ChallengeResponse,
  ProveResponse,
  VerifyResponse,
} from './api';
import {
  Step,
  renderNavigation,
  attachNavigationHandlers,
} from './components/navigation';
import { CapturedFace, renderWebcamPreview, renderWebcamControls } from './components/webcam';
import { renderHomeScreen, attachHomeHandlers } from './screens/home';
import {
  EnrollmentPhase,
  EnrollmentMode,
  renderEnrollmentScreen,
  attachEnrollmentHandlers,
  initEnrollmentWebcam,
  captureEnrollmentFrame,
  stopEnrollmentWebcam,
} from './screens/enrollment';
import {
  AuthPhase,
  renderAuthenticationScreen,
  attachAuthenticationHandlers,
  updateProofProgress,
  updateLivenessStatus,
  showLivenessGuide,
  showLivenessProcessing,
  updateFlashDot,
  initAuthWebcam,
  captureAuthFrame,
  stopAuthWebcam,
} from './screens/authentication';
import {
  renderVerificationScreen,
  attachVerificationHandlers,
} from './screens/verification';
import { performSpatialFlash, SpatialFlashCapture } from './components/screenFlash';
import {
  deriveFlashPattern,
  computeClientCommitment,
  bufferToHex,
  hexToBuffer,
  FlashRound,
} from './crypto/flashChallenge';

// Application state
interface AppState {
  currentStep: Step;
  completedSteps: Set<Step>;
  isLoading: boolean;
  error: string | null;

  // Enrollment
  enrollmentMode: EnrollmentMode;
  enrollmentPhase: EnrollmentPhase;
  enrollCapturedFace: CapturedFace | null;
  enrollWebcamError: string | null;
  sessionId: string | null;
  enrollResult: EnrollResponse | null;
  fuzzyEnrollResult: FuzzyEnrollResponse | null;

  // Fuzzy verify
  fuzzyVerifyResult: FuzzyVerifyResponse | null;

  // Authentication
  authPhase: AuthPhase;
  authCapturedFace: CapturedFace | null;
  authWebcamError: string | null;
  challenge: ChallengeResponse | null;
  proof: ProveResponse | null;

  // Spatial flash liveness
  cNonce: Uint8Array | null;
  flashRounds: FlashRound[] | null;
  spatialCapture: SpatialFlashCapture | null;

  // Verification
  verifyResult: VerifyResponse | null;
}

const state: AppState = {
  currentStep: 'home',
  completedSteps: new Set(),
  isLoading: false,
  error: null,
  enrollmentMode: 'pedersen',
  enrollmentPhase: 'capture',
  enrollCapturedFace: null,
  enrollWebcamError: null,
  sessionId: null,
  enrollResult: null,
  fuzzyEnrollResult: null,
  fuzzyVerifyResult: null,
  authPhase: 'ready',
  authCapturedFace: null,
  authWebcamError: null,
  challenge: null,
  proof: null,
  cNonce: null,
  flashRounds: null,
  spatialCapture: null,
  verifyResult: null,
};

function render(): void {
  const app = document.getElementById('app');
  if (!app) return;

  let content = '';

  // Navigation (shown after home)
  if (state.currentStep !== 'home') {
    content += renderNavigation(
      state.currentStep,
      state.completedSteps,
      navigateTo
    );
  }

  // Main content
  switch (state.currentStep) {
    case 'home':
      content += renderHomeScreen(() => navigateTo('enrollment'));
      break;
    case 'enrollment':
      content += renderEnrollmentScreen(
        state.enrollmentPhase,
        state.isLoading,
        state.enrollCapturedFace,
        state.enrollResult,
        state.fuzzyEnrollResult,
        state.error,
        state.enrollWebcamError,
        state.enrollmentMode
      );
      break;
    case 'authentication':
      if (state.enrollmentMode === 'fuzzy') {
        content += renderFuzzyVerifyScreen(
          state.authPhase,
          state.isLoading,
          state.authCapturedFace,
          state.fuzzyVerifyResult,
          state.error,
          state.authWebcamError
        );
      } else {
        content += renderAuthenticationScreen(
          state.authPhase,
          state.isLoading,
          state.challenge,
          state.authCapturedFace,
          state.proof,
          state.error,
          state.authWebcamError
        );
      }
      break;
    case 'verification':
      content += renderVerificationScreen(
        state.proof,
        state.isLoading,
        state.verifyResult,
        state.error,
        state.flashRounds
      );
      break;
  }

  content += `<footer class="site-footer">Made by <a href="https://anuna.io" target="_blank" rel="noopener">Anuna Research</a> &middot; <a href="https://codeberg.org/anuna/sable" target="_blank" rel="noopener">Open Source (Apache 2.0)</a></footer>`;

  app.innerHTML = content;

  // Attach handlers
  if (state.currentStep !== 'home') {
    attachNavigationHandlers(navigateTo);
  }

  switch (state.currentStep) {
    case 'home':
      attachHomeHandlers(() => navigateTo('enrollment'));
      break;
    case 'enrollment':
      attachEnrollmentHandlers(
        handleEnrollCapture,
        handleEnrollRetake,
        state.enrollmentMode === 'fuzzy' ? handleFuzzyEnroll : handleEnroll,
        () => navigateTo('authentication'),
        handleEnrollRetryCamera,
        state.enrollCapturedFace,
        handleModeChange
      );
      // Initialize webcam after render if in capture phase
      if (state.enrollmentPhase === 'capture' && !state.enrollResult && !state.fuzzyEnrollResult && !state.enrollWebcamError) {
        initEnrollmentWebcamAsync();
      }
      break;
    case 'authentication':
      if (state.enrollmentMode === 'fuzzy') {
        attachFuzzyVerifyHandlers();
        // Initialize webcam for fuzzy verify capture phase
        if (state.authPhase === 'capturing' && !state.authCapturedFace && !state.authWebcamError) {
          initAuthWebcamAsync();
        }
      } else {
        attachAuthenticationHandlers(
          handleStartAuth,
          handleAuthCapture,
          handleAuthRetake,
          handleProve,
          () => navigateTo('verification'),
          handleAuthRetryCamera,
          state.authCapturedFace,
          handleLivenessConsent
        );
        // Initialize webcam after render if in capturing phase
        if (state.authPhase === 'capturing' && !state.authCapturedFace && !state.authWebcamError) {
          initAuthWebcamAsync();
        }
      }
      break;
    case 'verification':
      attachVerificationHandlers(handleVerify, handleRestart);
      break;
  }
}

function navigateTo(step: Step): void {
  // Clean up webcam when leaving screens
  if (state.currentStep === 'enrollment') {
    stopEnrollmentWebcam();
  } else if (state.currentStep === 'authentication') {
    stopAuthWebcam();
  }

  state.currentStep = step;
  state.error = null;

  // Reset phase states when navigating to screens
  if (step === 'enrollment' && !state.enrollResult && !state.fuzzyEnrollResult) {
    state.enrollmentPhase = 'capture';
    state.enrollCapturedFace = null;
    state.enrollWebcamError = null;
  }
  if (step === 'authentication' && !state.proof && !state.fuzzyVerifyResult) {
    // In fuzzy mode, skip challenge phase and go straight to capture
    state.authPhase = state.enrollmentMode === 'fuzzy' ? 'capturing' : 'ready';
    state.authCapturedFace = null;
    state.authWebcamError = null;
  }

  render();
}

// ============================================================================
// Enrollment Handlers
// ============================================================================

async function initEnrollmentWebcamAsync(): Promise<void> {
  try {
    await initEnrollmentWebcam();
  } catch (err) {
    state.enrollWebcamError = err instanceof Error ? err.message : 'Camera access failed';
    render();
  }
}

function handleEnrollCapture(): void {
  const captured = captureEnrollmentFrame();
  if (captured) {
    state.enrollCapturedFace = captured;
    state.enrollmentPhase = 'preview';
    stopEnrollmentWebcam();
    render();
  }
}

function handleEnrollRetake(): void {
  state.enrollCapturedFace = null;
  state.enrollmentPhase = 'capture';
  state.enrollWebcamError = null;
  render();
}

function handleEnrollRetryCamera(): void {
  state.enrollWebcamError = null;
  state.enrollmentPhase = 'capture';
  render();
}

function handleModeChange(mode: EnrollmentMode): void {
  state.enrollmentMode = mode;
  render();
}

async function handleFuzzyEnroll(face: CapturedFace): Promise<void> {
  state.isLoading = true;
  state.error = null;
  render();

  try {
    const result = await api.fuzzyEnroll({
      user_id: 'webcam-user',
      face_embedding: face.embedding,
    });
    state.fuzzyEnrollResult = result;
    state.sessionId = result.session_id;
    state.enrollmentPhase = 'success';
    state.completedSteps.add('enrollment');
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'Fuzzy enrollment failed';
  } finally {
    state.isLoading = false;
    render();
  }
}

async function handleEnroll(face: CapturedFace): Promise<void> {
  state.isLoading = true;
  state.error = null;
  render();

  try {
    const result = await api.enroll({
      user_id: 'webcam-user',
      face_embedding: face.embedding,
    });
    state.enrollResult = result;
    state.sessionId = result.session_id;
    state.enrollmentPhase = 'success';
    state.completedSteps.add('enrollment');
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'Enrollment failed';
  } finally {
    state.isLoading = false;
    render();
  }
}

// ============================================================================
// Authentication Handlers
// ============================================================================

async function handleStartAuth(): Promise<void> {
  if (!state.sessionId) {
    state.error = 'No active session. Please enroll first.';
    render();
    return;
  }

  state.isLoading = true;
  state.error = null;
  state.authPhase = 'challenge';
  render();

  try {
    // Step 1: Generate client nonce and commitment
    const cNonce = new Uint8Array(32);
    crypto.getRandomValues(cNonce);
    state.cNonce = cNonce;

    const clientCommitment = await computeClientCommitment(cNonce);

    // Step 2: Get challenge with client commitment
    const challenge = await api.getChallenge({
      session_id: state.sessionId,
      client_commitment: clientCommitment,
    });
    state.challenge = challenge;

    // Step 3: Derive flash pattern from c_nonce and s_nonce
    const sNonce = hexToBuffer(challenge.nonce_hex);
    state.flashRounds = await deriveFlashPattern(cNonce, sNonce);

    state.isLoading = false;

    // Step 4: Move to capturing phase
    state.authPhase = 'capturing';
    render();
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'Failed to get challenge';
    state.authPhase = 'ready';
    state.isLoading = false;
    render();
  }
}

async function initAuthWebcamAsync(): Promise<void> {
  try {
    await initAuthWebcam();
  } catch (err) {
    state.authWebcamError = err instanceof Error ? err.message : 'Camera access failed';
    render();
  }
}

function handleAuthCapture(): void {
  const captured = captureAuthFrame();
  if (captured) {
    state.authCapturedFace = captured;
    stopAuthWebcam();
    render();
  }
}

function handleAuthRetake(): void {
  state.authCapturedFace = null;
  state.authWebcamError = null;
  state.error = null;
  render();
}

function handleAuthRetryCamera(): void {
  state.authWebcamError = null;
  render();
}

async function handleProve(face: CapturedFace): Promise<void> {
  if (!state.challenge) {
    state.error = 'No challenge available';
    render();
    return;
  }

  // Transition to liveness phase first
  state.isLoading = true;
  state.error = null;
  state.authPhase = 'liveness';
  // Store face for use after liveness check
  state.authCapturedFace = face;
  render();
  // Liveness check will be triggered by render() -> runLivenessCheck()
}

// Guard to prevent re-entrant liveness checks
let livenessRunning = false;

/**
 * Called when the user consents to the liveness check (clicks the "OK" button).
 * This starts the camera, shows the face guide, and runs the spatial flash sequence.
 */
async function handleLivenessConsent(): Promise<void> {
  if (livenessRunning) return;
  livenessRunning = true;

  try {
    // Show face guide (hide consent notice)
    showLivenessGuide();

    // Open camera for spatial flash
    const video = document.getElementById('liveness-video') as HTMLVideoElement;
    if (!video) {
      throw new Error('Liveness video element not found');
    }

    updateLivenessStatus('Opening camera...');

    const stream = await navigator.mediaDevices.getUserMedia({
      video: { width: { ideal: 640 }, height: { ideal: 480 }, facingMode: 'user' },
      audio: false,
    });

    video.srcObject = stream;
    await video.play();

    // Wait for video to be ready
    await new Promise<void>((resolve) => {
      if (video.readyState >= 2) {
        resolve();
      } else {
        video.onloadeddata = () => resolve();
      }
    });

    // Small delay for camera to stabilize and user to position face
    updateLivenessStatus('Position your face in the oval...');
    await sleep(1000);

    if (!state.flashRounds || state.flashRounds.length !== 3) {
      throw new Error('Flash pattern not derived');
    }

    updateLivenessStatus('Starting spatial flash...');

    // Perform the spatial flash capture with progress dots
    const capture = await performSpatialFlashWithProgress(state.flashRounds, video);
    state.spatialCapture = capture;

    // Stop webcam
    stream.getTracks().forEach(track => track.stop());
    video.srcObject = null;

    showLivenessProcessing('Liveness capture complete. Generating proof...');
    await sleep(500);

    // Proceed to proof generation with spatial flash data
    await generateProof();

  } catch (err) {
    state.error = err instanceof Error ? err.message : 'Liveness check failed';
    state.authCapturedFace = null;
    // Challenge is single-use and may have expired — reset to fetch a fresh one
    state.challenge = null;
    state.cNonce = null;
    state.flashRounds = null;
    state.spatialCapture = null;
    state.authPhase = 'ready';
    state.isLoading = false;
    render();
  } finally {
    livenessRunning = false;
  }
}

/**
 * Perform spatial flash with progress dot updates.
 */
async function performSpatialFlashWithProgress(
  rounds: FlashRound[],
  video: HTMLVideoElement
): Promise<SpatialFlashCapture> {
  // We wrap performSpatialFlash but update dots after each round.
  // Since performSpatialFlash handles the full sequence internally,
  // we update dots based on timing estimates.

  // Start the spatial flash
  const capturePromise = performSpatialFlash(rounds, video);

  // Update progress dots at approximate intervals (~350ms per round)
  const roundDuration = 350;
  for (let i = 0; i < rounds.length; i++) {
    await sleep(roundDuration);
    updateFlashDot(i);
    updateLivenessStatus(`Round ${i + 1} of ${rounds.length} captured`);
  }

  return capturePromise;
}

async function generateProof(): Promise<void> {
  if (!state.challenge || !state.authCapturedFace) {
    state.error = 'Missing challenge or face data';
    state.authPhase = 'capturing';
    state.isLoading = false;
    render();
    return;
  }

  state.authPhase = 'proving';
  render();

  try {
    // Simulate progress while waiting for backend
    await simulateProofProgress();

    // Build prove request with spatial flash data
    const proveRequest: {
      challenge_id: string;
      face_embedding?: number[];
      c_nonce?: string;
      flash_frames?: string[];
    } = {
      challenge_id: state.challenge.challenge_id,
      face_embedding: state.authCapturedFace.embedding,
    };

    // Include spatial flash data if available
    if (state.cNonce && state.spatialCapture) {
      proveRequest.c_nonce = bufferToHex(state.cNonce);
      // flash_frames: [baseline, round0, round1, round2]
      proveRequest.flash_frames = [
        state.spatialCapture.baselineDataUrl,
        ...state.spatialCapture.roundFrames,
      ];
    }

    const proof = await api.prove(proveRequest);

    state.proof = proof;
    state.authPhase = 'complete';
    state.completedSteps.add('authentication');
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'Proof generation failed';
    // Challenge is single-use — reset to fetch a fresh one on retry
    state.challenge = null;
    state.cNonce = null;
    state.flashRounds = null;
    state.spatialCapture = null;
    state.authPhase = 'ready';
  } finally {
    state.isLoading = false;
    render();
  }
}

async function simulateProofProgress(): Promise<void> {
  const steps = [
    { percent: 10, status: 'Processing face embedding...' },
    { percent: 25, status: 'Converting to ZK features...' },
    { percent: 40, status: 'Computing Poseidon hash...' },
    { percent: 55, status: 'Building Halo2 circuit...' },
    { percent: 70, status: 'Generating witness...' },
    { percent: 85, status: 'Computing proof...' },
    { percent: 95, status: 'Finalizing...' },
  ];

  for (const step of steps) {
    updateProofProgress(step.percent, step.status);
    await sleep(120);
  }
}

// ============================================================================
// Verification Handlers
// ============================================================================

async function handleVerify(): Promise<void> {
  if (!state.proof) {
    state.error = 'No proof available. Please authenticate first.';
    render();
    return;
  }

  state.isLoading = true;
  state.error = null;
  render();

  try {
    const result = await api.verify({
      proof_hex: state.proof.proof_hex,
      public_inputs_hex: state.proof.public_inputs_hex,
      challenge_id: state.challenge?.challenge_id,
      session_id: state.sessionId ?? undefined,
    });
    state.verifyResult = result;
    state.completedSteps.add('verification');
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'Verification failed';
  } finally {
    state.isLoading = false;
    render();
  }
}

function handleRestart(): void {
  // Clean up webcams
  stopEnrollmentWebcam();
  stopAuthWebcam();

  // Reset state
  state.currentStep = 'home';
  state.completedSteps.clear();
  state.isLoading = false;
  state.error = null;
  state.enrollmentMode = 'pedersen';
  state.enrollmentPhase = 'capture';
  state.enrollCapturedFace = null;
  state.enrollWebcamError = null;
  state.sessionId = null;
  state.enrollResult = null;
  state.fuzzyEnrollResult = null;
  state.fuzzyVerifyResult = null;
  state.authPhase = 'ready';
  state.authCapturedFace = null;
  state.authWebcamError = null;
  state.challenge = null;
  state.proof = null;
  state.cNonce = null;
  state.flashRounds = null;
  state.spatialCapture = null;
  state.verifyResult = null;
  render();
}

// ============================================================================
// Fuzzy Verify Screen (simplified auth for fuzzy mode)
// ============================================================================

function renderFuzzyVerifyScreen(
  phase: AuthPhase,
  isLoading: boolean,
  capturedFace: CapturedFace | null,
  fuzzyResult: FuzzyVerifyResponse | null,
  error: string | null,
  webcamError: string | null
): string {
  return `
    <div class="card">
      <h2>Step 2: Fuzzy Verification</h2>
      <p>
        Capture a new face scan to verify against the fuzzy commitment.
        The system reproduces the commitment from the new scan using the stored helper data.
        No ZK proof or liveness check is needed for this mode.
      </p>

      ${renderFuzzyVerifyPhase(phase, isLoading, capturedFace, fuzzyResult, webcamError)}

      ${error ? `
        <div class="badge badge-error" style="margin-top: 1rem; display: block; padding: 0.75rem;">
          Error: ${error}
        </div>
      ` : ''}
    </div>

    <div class="card">
      <h3>How Fuzzy Verification Works</h3>
      <ol style="padding-left: 1.5rem; color: var(--text-secondary);">
        <li style="margin-bottom: 0.75rem;">
          <strong>Face Capture:</strong> A new 1024-dimensional embedding is extracted
        </li>
        <li style="margin-bottom: 0.75rem;">
          <strong>Error Correction:</strong> Reed-Solomon decoding recovers the original codeword from the noisy scan + helper data
        </li>
        <li style="margin-bottom: 0.75rem;">
          <strong>Commitment Comparison:</strong> SHA-256(recovered codeword) is compared to the stored commitment
        </li>
      </ol>
    </div>
  `;
}

function renderFuzzyVerifyPhase(
  _phase: AuthPhase,
  isLoading: boolean,
  capturedFace: CapturedFace | null,
  fuzzyResult: FuzzyVerifyResponse | null,
  webcamError: string | null
): string {
  // Show result if we have one
  if (fuzzyResult) {
    return `
      <div class="fade-in">
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;">
          <span class="badge ${fuzzyResult.matched ? 'badge-success' : 'badge-error'}">
            ${fuzzyResult.matched ? 'Match Confirmed' : 'No Match'}
          </span>
        </div>

        ${fuzzyResult.matched && fuzzyResult.commitment_hex ? `
          <h3>Reproduced Commitment</h3>
          <div class="code" style="word-break: break-all; font-size: 0.75rem;">
            ${fuzzyResult.commitment_hex}
          </div>
          <p style="font-size: 0.875rem; margin-top: 0.5rem;">
            The same deterministic commitment was reproduced from the new scan,
            confirming this is the same person.
          </p>
        ` : `
          <p style="font-size: 0.875rem;">
            The scan could not reproduce the original commitment.
            The biometric distance was too large for error correction.
          </p>
        `}

        <div class="timing-grid" style="margin-top: 1rem;">
          <div class="timing-item">
            <div class="timing-value">${fuzzyResult.timing_ms.toFixed(2)}ms</div>
            <div class="timing-label">Verification Time</div>
          </div>
        </div>

        <div style="margin-top: 1.5rem;">
          <button class="btn btn-primary" id="fuzzy-restart">
            Start Over
          </button>
        </div>
      </div>
    `;
  }

  if (webcamError) {
    return `
      <div class="webcam-error">
        <p><strong>Camera Error:</strong> ${webcamError}</p>
        <button class="btn btn-primary" id="retry-auth-camera-btn" style="margin-top: 1rem;">
          Retry Camera Access
        </button>
      </div>
    `;
  }

  // Show captured face with verify button
  if (capturedFace) {
    return `
      <div class="fade-in">
        ${renderWebcamPreview(capturedFace)}
        <div class="webcam-controls">
          <button class="btn btn-secondary" id="retake-auth-btn" ${isLoading ? 'disabled' : ''}>
            Retake
          </button>
          <button class="btn btn-primary" id="fuzzy-verify-btn" ${isLoading ? 'disabled' : ''}>
            ${isLoading ? '<span class="spinner"></span> Verifying...' : 'Verify Match'}
          </button>
        </div>
      </div>
    `;
  }

  // Webcam capture phase
  return `
    <div class="fade-in">
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
}

function attachFuzzyVerifyHandlers(): void {
  // Capture button
  document.getElementById('capture-btn')?.addEventListener('click', handleAuthCapture);

  // Retake
  document.getElementById('retake-auth-btn')?.addEventListener('click', handleAuthRetake);

  // Retry camera
  document.getElementById('retry-auth-camera-btn')?.addEventListener('click', handleAuthRetryCamera);

  // Verify button
  document.getElementById('fuzzy-verify-btn')?.addEventListener('click', () => {
    if (state.authCapturedFace) {
      handleFuzzyVerify(state.authCapturedFace);
    }
  });

  // Restart button
  document.getElementById('fuzzy-restart')?.addEventListener('click', handleRestart);
}

async function handleFuzzyVerify(face: CapturedFace): Promise<void> {
  if (!state.sessionId) {
    state.error = 'No active session. Please enroll first.';
    render();
    return;
  }

  state.isLoading = true;
  state.error = null;
  render();

  try {
    const result = await api.fuzzyVerify({
      session_id: state.sessionId,
      face_embedding: face.embedding,
    });
    state.fuzzyVerifyResult = result;
    state.completedSteps.add('authentication');
    if (result.matched) {
      state.completedSteps.add('verification');
    }
  } catch (err) {
    state.error = err instanceof Error ? err.message : 'Fuzzy verification failed';
  } finally {
    state.isLoading = false;
    render();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  // Check API health on load
  api.health().then(() => {
    console.log('SABLE Demo API connected');
  }).catch(err => {
    console.warn('API not available:', err.message);
  });

  render();
});
