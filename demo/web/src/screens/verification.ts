import { ProveResponse, VerifyResponse, RegionMatchScore } from '../api';
import { FlashRound } from '../crypto/flashChallenge';

/**
 * Convert an RGB tuple to a CSS color string.
 */
function rgbCss(color: [number, number, number]): string {
  return `rgb(${color[0]}, ${color[1]}, ${color[2]})`;
}

/**
 * Render a single flash round as a 2×2 quadrant card.
 */
function renderFlashCard(round: FlashRound, index: number): string {
  const splitX = 50 + (round.offsetX * 30 - 15);
  const splitY = 50 + (round.offsetY * 30 - 15);
  return `
    <div class="flash-card" style="display:grid; grid-template-columns:${splitX}% ${100-splitX}%; grid-template-rows:${splitY}% ${100-splitY}%; overflow:hidden;">
      <div style="background:${rgbCss(round.tlColor)};"></div>
      <div style="background:${rgbCss(round.trColor)};"></div>
      <div style="background:${rgbCss(round.blColor)};"></div>
      <div style="background:${rgbCss(round.brColor)};"></div>
      <div class="flash-card-label" style="grid-column:1/-1; grid-row:1/-1; place-self:center;">Round ${index + 1}</div>
    </div>
  `;
}

/**
 * Render per-region match scores as horizontal bars (4 quadrants per round).
 */
function renderRegionScores(scores: RegionMatchScore[]): string {
  const renderBar = (label: string, value: number) => `
    <div class="region-score-bar-group">
      <span class="region-score-bar-label">${label}</span>
      <div class="region-score-track">
        <div class="region-score-fill" style="width: ${Math.min(value * 100, 100).toFixed(0)}%; background: ${value >= 0.5 ? 'var(--accent-success)' : 'var(--accent-error)'};"></div>
      </div>
      <span class="region-score-pct">${(value * 100).toFixed(0)}%</span>
    </div>
  `;

  return scores.map(s => `
    <div class="region-score-row">
      <div class="region-score-label">Round ${s.round}</div>
      <div class="region-score-bars">
        ${renderBar('TL', s.tl_score)}
        ${renderBar('TR', s.tr_score)}
        ${renderBar('BL', s.bl_score)}
        ${renderBar('BR', s.br_score)}
      </div>
    </div>
  `).join('');
}

/**
 * Render the spatial differentiation score as a labeled gauge bar.
 */
function renderSpatialDiffScore(score: number): string {
  const pct = Math.min(score * 100, 100).toFixed(0);
  const color = score >= 0.5 ? 'var(--accent-success)' : score >= 0.3 ? 'var(--accent-warning)' : 'var(--accent-error)';
  return `
    <div class="spatial-diff-score">
      <div class="spatial-diff-label">Spatial Differentiation</div>
      <div class="spatial-diff-track">
        <div class="spatial-diff-fill" style="width: ${pct}%; background: ${color};"></div>
      </div>
      <div class="spatial-diff-value" style="color: ${color};">${pct}%</div>
    </div>
  `;
}

/**
 * Build the complete spatial color challenge section.
 * Only rendered when color_challenge_passed is present.
 */
function renderSpatialLivenessSection(
  proof: ProveResponse,
  flashRounds: FlashRound[] | null,
): string {
  const passed = proof.color_challenge_passed;
  if (passed == null) return '';

  return `
    <div class="card">
      <h3>Spatial Color Challenge</h3>
      <div class="spatial-badge ${passed ? 'spatial-badge-pass' : 'spatial-badge-fail'}">
        <span class="spatial-badge-icon">${passed ? '\u2713' : '\u2717'}</span>
        <span>${passed ? 'Passed' : 'Failed'}</span>
      </div>

      ${flashRounds && flashRounds.length === 3 ? `
        <div class="flash-rounds">
          <div class="flash-rounds-label">Flash Pattern</div>
          <div class="flash-cards-row">
            ${flashRounds.map((r, i) => renderFlashCard(r, i)).join('')}
          </div>
        </div>
      ` : ''}

      ${proof.region_match_scores && proof.region_match_scores.length > 0 ? `
        <div class="region-scores-section">
          <div class="region-scores-label">Per-Region Match Confidence</div>
          ${renderRegionScores(proof.region_match_scores)}
        </div>
      ` : ''}

      ${proof.spatial_differentiation_score != null ? `
        ${renderSpatialDiffScore(proof.spatial_differentiation_score)}
      ` : ''}
    </div>
  `;
}

export function renderVerificationScreen(
  proof: ProveResponse | null,
  isLoading: boolean,
  result: VerifyResponse | null,
  error: string | null,
  flashRounds: FlashRound[] | null
): string {
  // Augment what_was_proven / what_stayed_private with spatial items when applicable
  const extraProven: string[] = [];
  const extraPrivate: string[] = [];
  if (proof?.liveness_proved_in_zk) {
    // ZK liveness — server-side text already covers this, just add spatial geometry note
    extraProven.push('Face reflects spatially structured light consistent with 3D geometry');
    extraPrivate.push('Per-region facial reflectance signals (proven without revealing)');
  } else if (proof?.color_challenge_passed != null) {
    extraProven.push('Face reflects spatially structured light consistent with 3D geometry');
    extraPrivate.push('Per-region reflectance signals');
  }

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
            ${result.details.liveness_proved_in_zk ? `
              <div class="timing-item">
                <div class="timing-value" style="color: var(--accent-success);">
                  \u2713
                </div>
                <div class="timing-label">ZK Liveness</div>
              </div>
            ` : result.details.color_challenge_passed != null ? `
              <div class="timing-item">
                <div class="timing-value" style="color: ${result.details.color_challenge_passed ? 'var(--accent-success)' : 'var(--accent-error)'};">
                  ${result.details.color_challenge_passed ? '\u2713' : '\u2717'}
                </div>
                <div class="timing-label">Spatial Liveness</div>
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

    ${proof ? renderSpatialLivenessSection(proof, flashRounds) : ''}

    ${proof ? `
      <div class="card">
        <h3>What Was Proven (Public)</h3>
        <ul class="proof-list">
          ${[...proof.what_was_proven, ...extraProven].map(item => `
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
          ${[...proof.what_stayed_private, ...extraPrivate].map(item => `
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
