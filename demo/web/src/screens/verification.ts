import { ProveResponse, VerifyResponse } from '../api';

export function renderVerificationScreen(
  proof: ProveResponse | null,
  isLoading: boolean,
  result: VerifyResponse | null,
  error: string | null
): string {
  return `
    <div class="card">
      <h2>Step 3: Verification</h2>
      <p>
        The verifier checks the zero-knowledge proof. If valid, they learn only that
        authentication succeeded - nothing about your actual biometric data.
      </p>

      ${!result ? `
        <button class="btn btn-primary" id="verify-btn" ${isLoading ? 'disabled' : ''}>
          ${isLoading ? '<span class="spinner"></span> Verifying...' : 'Verify Proof'}
        </button>
      ` : `
        <div class="fade-in">
          <div class="verification-result ${result.valid ? 'success' : 'failure'}">
            <div class="icon">${result.valid ? '\u2713' : '\u2717'}</div>
            <h2 style="margin-bottom: 0.5rem;">${result.valid ? 'Verification Successful' : 'Verification Failed'}</h2>
            <p>Verified in ${result.verification_time_ms.toFixed(2)}ms</p>
          </div>

          <div class="timing-grid" style="margin: 2rem 0;">
            <div class="timing-item">
              <div class="timing-value" style="color: ${result.details.commitment_valid ? 'var(--accent-success)' : 'var(--accent-error)'};">
                ${result.details.commitment_valid ? '\u2713' : '\u2717'}
              </div>
              <div class="timing-label">Commitment Valid</div>
            </div>
            <div class="timing-item">
              <div class="timing-value" style="color: ${result.details.distance_check_passed ? 'var(--accent-success)' : 'var(--accent-error)'};">
                ${result.details.distance_check_passed ? '\u2713' : '\u2717'}
              </div>
              <div class="timing-label">Distance Check</div>
            </div>
            <div class="timing-item">
              <div class="timing-value" style="color: ${result.details.temporal_check_passed ? 'var(--accent-success)' : 'var(--accent-error)'};">
                ${result.details.temporal_check_passed ? '\u2713' : '\u2717'}
              </div>
              <div class="timing-label">Temporal Check</div>
            </div>
            <div class="timing-item">
              <div class="timing-value" style="color: ${result.details.quality_check_passed ? 'var(--accent-success)' : 'var(--accent-error)'};">
                ${result.details.quality_check_passed ? '\u2713' : '\u2717'}
              </div>
              <div class="timing-label">Quality Check</div>
            </div>
            ${result.details.liveness_check_passed != null ? `
              <div class="timing-item">
                <div class="timing-value" style="color: ${result.details.liveness_check_passed ? 'var(--accent-success)' : 'var(--accent-error)'};">
                  ${result.details.liveness_check_passed ? '\u2713' : '\u2717'}
                </div>
                <div class="timing-label">Liveness Check</div>
              </div>
            ` : ''}
          </div>
        </div>
      `}

      ${error ? `
        <div class="badge badge-error" style="margin-top: 1rem; display: block; padding: 0.75rem;">
          Error: ${error}
        </div>
      ` : ''}
    </div>

    ${proof ? `
      <div class="card">
        <h3>What Was Proven (Public)</h3>
        <ul class="proof-list">
          ${proof.what_was_proven.map(item => `
            <li class="proven">
              <span class="icon">\u2713</span>
              <span>${item}</span>
            </li>
          `).join('')}
        </ul>
      </div>

      <div class="card">
        <h3>What Stayed Private (Hidden)</h3>
        <ul class="proof-list">
          ${proof.what_stayed_private.map(item => `
            <li class="private">
              <span class="icon">\uD83D\uDD12</span>
              <span>${item}</span>
            </li>
          `).join('')}
        </ul>
      </div>
    ` : ''}

    <div class="card">
      <h3>The Power of Zero-Knowledge</h3>
      <p>
        This demo illustrates the core principle of zero-knowledge proofs: proving
        statements without revealing underlying data. In SABLE's case:
      </p>
      <ul style="padding-left: 1.5rem; color: var(--text-secondary); margin: 1rem 0;">
        <li style="margin-bottom: 0.5rem;">
          <strong>Prover knows:</strong> Biometric features, salt, exact distance, liveness signals
        </li>
        <li style="margin-bottom: 0.5rem;">
          <strong>Verifier learns:</strong> Only that authentication and liveness checks passed
        </li>
        <li style="margin-bottom: 0.5rem;">
          <strong>No one else learns:</strong> Anything - the proof is non-transferable
        </li>
      </ul>
      <p>
        Even if an attacker intercepts the proof, they cannot extract biometric data
        or reuse the proof (due to the challenge nonce).
      </p>
    </div>

    <div style="text-align: center; margin-top: 2rem;">
      <button class="btn btn-secondary" id="restart-btn">
        Start Over
      </button>
    </div>
  `;
}

export function attachVerificationHandlers(
  onVerify: () => void,
  onRestart: () => void
): void {
  document.getElementById('verify-btn')?.addEventListener('click', onVerify);
  document.getElementById('restart-btn')?.addEventListener('click', onRestart);
}
