export function renderHomeScreen(_onStart: () => void): string {
  return `
    <div class="header">
      <h1>SABLE Demo</h1>
      <p class="subtitle">Privacy-Preserving Biometric Authentication with Zero-Knowledge Proofs</p>
    </div>

    <div class="card highlight">
      <h2>What is SABLE?</h2>
      <p>
        SABLE (Secure Attested Biometric Library for Edge) enables biometric authentication
        without exposing your actual biometric data. Using advanced cryptographic techniques,
        you can prove you're the right person without revealing <em>anything</em> about your
        biometric features.
      </p>
    </div>

    <div class="card">
      <h3>System Architecture</h3>
      <div class="arch-diagram">
        <div class="arch-gov-row">
          <div class="arch-node gov optional">
            <div class="arch-node-icon">&#x1F3DB;&#xFE0F;</div>
            <div class="arch-node-title">Government <span class="optional-tag">optional</span></div>
            <div class="arch-node-items">
              <span>Identity verification</span>
              <span>Issue Verifiable Credential</span>
            </div>
          </div>
        </div>

        <div class="arch-vert-arrow optional">
          <div class="arch-vert-line"></div>
          <div class="arch-vert-label">Verifiable Credential</div>
          <div class="arch-vert-tip"></div>
        </div>

        <div class="arch-flow">
          <div class="arch-node user">
            <div class="arch-node-icon">&#x1F464;</div>
            <div class="arch-node-title">You (User)</div>
            <div class="arch-node-items">
              <span>Camera capture</span>
              <span>Feature extraction</span>
              <span>Screen flash liveness</span>
              <span>Holds biometrics locally</span>
            </div>
          </div>

          <div class="arch-arrow">
            <div class="arch-arrow-line"></div>
          </div>

          <div class="arch-node engine">
            <div class="arch-node-icon">&#x1F510;</div>
            <div class="arch-node-title">ZK Engine</div>
            <div class="arch-node-items">
              <span>Poseidon hash</span>
              <span>Pedersen commit</span>
              <span>Halo2 proof</span>
            </div>
          </div>

          <div class="arch-arrow">
            <div class="arch-arrow-line"></div>
          </div>

          <div class="arch-node verifier">
            <div class="arch-node-icon">&#x2705;</div>
            <div class="arch-node-title">Verifier</div>
            <div class="arch-node-items">
              <span>Proof verification</span>
              <span>Credential check (if VC)</span>
              <span>Pass / Fail</span>
            </div>
          </div>
        </div>
      </div>

      <div class="privacy-note">
        &#x1F6E1;&#xFE0F; Biometric data never leaves you &mdash; only mathematical proofs and credentials cross the boundary
      </div>
    </div>

    <div class="card">
      <h3>Protocol Flow</h3>
      <div class="swimlane">
        <div class="swimlane-header">
          <div></div>
          <div class="swimlane-col-label gov-label">Government</div>
          <div></div>
          <div class="swimlane-col-label user-label">You (User)</div>
          <div></div>
          <div class="swimlane-col-label verifier-label">Verifier</div>
        </div>

        <!-- Phase 0: Issue — Optional government VC issuance -->
        <div class="swimlane-row optional-row">
          <div class="swim-phase phase-issue">Issue <span class="optional-tag">opt</span></div>
          <div class="swim-action optional">
            <div class="swim-action-title">Verify identity</div>
            <div class="swim-action-detail">Issue Verifiable Credential binding identity to biometric commitment</div>
          </div>
          <div class="swim-arrow optional"><div class="swim-arrow-right"></div></div>
          <div class="swim-action optional">
            <div class="swim-action-title">Receive VC</div>
            <div class="swim-action-detail">Store credential on device</div>
          </div>
          <div></div>
          <div class="swim-empty"></div>
        </div>

        <!-- Phase 2: Enroll — User captures biometrics, server commits -->
        <div class="swimlane-row">
          <div class="swim-phase phase-enroll">Enroll</div>
          <div class="swim-empty"></div>
          <div></div>
          <div class="swim-action">
            <div class="swim-action-title">Capture face</div>
            <div class="swim-action-detail">Extract 1024-dim embedding</div>
          </div>
          <div class="swim-arrow"><div class="swim-arrow-right"></div></div>
          <div class="swim-action">
            <div class="swim-action-title">Hash &amp; commit</div>
            <div class="swim-action-detail">Poseidon hash + Pedersen commitment</div>
          </div>
        </div>

        <!-- Phase 3: Auth — User captures + liveness, ZK proof generated -->
        <div class="swimlane-row">
          <div class="swim-phase phase-auth">Auth</div>
          <div class="swim-empty"></div>
          <div></div>
          <div class="swim-action">
            <div class="swim-action-title">Capture + flash</div>
            <div class="swim-action-detail">Screen flash liveness detection</div>
          </div>
          <div class="swim-arrow"><div class="swim-arrow-right"></div></div>
          <div class="swim-action">
            <div class="swim-action-title">Generate ZK proof</div>
            <div class="swim-action-detail">Halo2 proof in ~450ms, 2KB</div>
          </div>
        </div>

        <!-- Phase 4: Verify — Verifier checks proof + credential -->
        <div class="swimlane-row">
          <div class="swim-phase phase-verify">Verify</div>
          <div class="swim-empty"></div>
          <div></div>
          <div class="swim-action">
            <div class="swim-action-title">Receive result</div>
            <div class="swim-action-detail">Pass/fail only &mdash; no biometrics</div>
          </div>
          <div class="swim-arrow"><div class="swim-arrow-left"></div></div>
          <div class="swim-action">
            <div class="swim-action-title">Verify proof</div>
            <div class="swim-action-detail">~2ms BN254 verification (+ VC check if issued)</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Cryptographic Building Blocks</h3>
      <div class="timing-grid">
        <div class="timing-item">
          <div class="timing-value" style="font-size: 1rem;">Poseidon</div>
          <div class="timing-label">ZK-friendly hash (~16ms)</div>
        </div>
        <div class="timing-item">
          <div class="timing-value" style="font-size: 1rem;">Pedersen</div>
          <div class="timing-label">Hiding commitment (~140\u00B5s)</div>
        </div>
        <div class="timing-item">
          <div class="timing-value" style="font-size: 1rem;">Halo2</div>
          <div class="timing-label">ZK proof (~450ms)</div>
        </div>
        <div class="timing-item">
          <div class="timing-value" style="font-size: 1rem;">BN254</div>
          <div class="timing-label">Elliptic curve</div>
        </div>
      </div>
    </div>

    <div style="text-align: center; margin-top: 2rem;">
      <button class="btn btn-primary" id="start-demo" style="padding: 1rem 2rem; font-size: 1.125rem;">
        Start Interactive Demo
      </button>
    </div>
  `;
}

export function attachHomeHandlers(onStart: () => void): void {
  document.getElementById('start-demo')?.addEventListener('click', onStart);
}
