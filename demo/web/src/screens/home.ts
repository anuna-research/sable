import { setCredential } from '../api';

export function renderHomeScreen(_onStart: () => void): string {
  return `
    <div class="header">
      <h1>SABLE Demo</h1>
      <p class="subtitle">Experimental ZK Matching with Centralized Biometric Processing</p>
    </div>

    <div class="card highlight">
      <h2>What is SABLE?</h2>
      <p>
        This research demo uploads embeddings, captured frames and eye crops to the
        server. The server generates proofs of matching and liveness relations.
        Those proofs do not authenticate a camera or establish physical capture.
        Enrollment records expire after 15 minutes. On-device proving is not implemented.
      </p>
    </div>

    <div class="card">
      <h3>Intended Architecture (Not the Current Demo)</h3>
      <div class="arch-diagram">
        <div class="arch-gov-row">
          <div class="arch-node gov optional">
            <div class="arch-node-icon">&#x1F3DB;&#xFE0F;</div>
            <div class="arch-node-title">Government <span class="optional-tag">optional</span></div>
            <div class="arch-node-items">
              <span>Identity verification</span>
              <span>Issue VC with BBS+ signatures</span>
              <span>Enables selective disclosure</span>
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
              <span>Camera capture + liveness</span>
              <span>Feature extraction</span>
              <span>Choose what to reveal</span>
              <span>Biometrics + VC stay on device</span>
            </div>
          </div>

          <div class="arch-arrow">
            <div class="arch-arrow-line"></div>
          </div>

          <div class="arch-node engine">
            <div class="arch-node-icon">&#x1F510;</div>
            <div class="arch-node-title">ZK Engine</div>
            <div class="arch-node-items">
              <span>Poseidon hash + Pedersen commit</span>
              <span>Halo2 composite proof</span>
              <span>Biometric + credential predicates</span>
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
              <span>Sees only disclosed attributes</span>
              <span>Pass / Fail</span>
            </div>
          </div>
        </div>
      </div>

      <div class="privacy-note">
        &#x1F6E1;&#xFE0F; You control what is revealed &mdash; biometrics stay private, credential attributes are selectively disclosed
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
            <div class="swim-action-detail">Issue VC with BBS+ signatures (name, DOB, nationality, biometric commitment&hellip;)</div>
          </div>
          <div class="swim-arrow optional"><div class="swim-arrow-right"></div></div>
          <div class="swim-action optional">
            <div class="swim-action-title">Receive VC</div>
            <div class="swim-action-detail">Store multi-attribute credential on device</div>
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

        <!-- Phase 3: Auth — Coin-flip liveness + ZK proof generated -->
        <div class="swimlane-row">
          <div class="swim-phase phase-auth">Auth</div>
          <div class="swim-empty"></div>
          <div></div>
          <div class="swim-action">
            <div class="swim-action-title">Liveness challenge</div>
            <div class="swim-action-detail">Random split-screen color flash + 3D face geometry check</div>
          </div>
          <div class="swim-arrow"><div class="swim-arrow-right"></div></div>
          <div class="swim-action">
            <div class="swim-action-title">Generate ZK proof</div>
            <div class="swim-action-detail">Face match + liveness in ~250ms, 2KB</div>
          </div>
        </div>

        <!-- Phase 4: Present — Optional selective disclosure -->
        <div class="swimlane-row optional-row">
          <div class="swim-phase phase-present">Present <span class="optional-tag">opt</span></div>
          <div class="swim-empty"></div>
          <div></div>
          <div class="swim-action optional">
            <div class="swim-action-title">Select attributes</div>
            <div class="swim-action-detail">Choose what to reveal (e.g. &ldquo;over 18&rdquo; without name or DOB)</div>
          </div>
          <div class="swim-arrow optional"><div class="swim-arrow-right"></div></div>
          <div class="swim-action optional">
            <div class="swim-action-title">Receive disclosure</div>
            <div class="swim-action-detail">Only chosen predicates &mdash; all other attributes hidden</div>
          </div>
        </div>

        <!-- Phase 5: Verify — Verifier checks proof + optional credential -->
        <div class="swimlane-row">
          <div class="swim-phase phase-verify">Verify</div>
          <div class="swim-empty"></div>
          <div></div>
          <div class="swim-action">
            <div class="swim-action-title">Receive result</div>
            <div class="swim-action-detail">Pass/fail only &mdash; no biometrics exposed</div>
          </div>
          <div class="swim-arrow"><div class="swim-arrow-left"></div></div>
          <div class="swim-action">
            <div class="swim-action-title">Verify composite proof</div>
            <div class="swim-action-detail">Biometric match + disclosed predicates</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Selective Disclosure</h3>
      <p>With a government-issued credential, you choose exactly what the verifier learns. The ZK proof covers both biometric match <em>and</em> credential predicates in a single proof.</p>
      <div class="disclosure-example">
        <div class="disclosure-header">
          <span class="disclosure-title">Government Credential</span>
          <span class="optional-tag">example</span>
        </div>
        <div class="disclosure-fields">
          <div class="disclosure-field hidden">
            <span class="disclosure-label">Full Name</span>
            <span class="disclosure-value redacted">&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;</span>
            <span class="disclosure-status">hidden</span>
          </div>
          <div class="disclosure-field hidden">
            <span class="disclosure-label">Date of Birth</span>
            <span class="disclosure-value redacted">&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;</span>
            <span class="disclosure-status">hidden</span>
          </div>
          <div class="disclosure-field revealed">
            <span class="disclosure-label">Age Check</span>
            <span class="disclosure-value">&ge; 18</span>
            <span class="disclosure-status">predicate</span>
          </div>
          <div class="disclosure-field revealed">
            <span class="disclosure-label">Nationality</span>
            <span class="disclosure-value">Valid</span>
            <span class="disclosure-status">predicate</span>
          </div>
          <div class="disclosure-field hidden">
            <span class="disclosure-label">ID Number</span>
            <span class="disclosure-value redacted">&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;&#x2588;</span>
            <span class="disclosure-status">hidden</span>
          </div>
          <div class="disclosure-field zk">
            <span class="disclosure-label">Biometric</span>
            <span class="disclosure-value">Match &#x2713;</span>
            <span class="disclosure-status">ZK proof</span>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Liveness Detection</h3>
      <p>SABLE makes it significantly harder to spoof authentication with a photo, video, or screen replay by using a challenge&ndash;response color-flash protocol. It is not foolproof &mdash; sophisticated 3D masks or real-time video manipulation may still defeat it &mdash; but it raises the bar well beyond static presentation attacks. The circuit checks supplied reflectance values; the demo server receives the underlying images.</p>

      <div class="liveness-steps">
        <div class="liveness-step">
          <div class="liveness-step-num">1</div>
          <div class="liveness-step-body">
            <div class="liveness-step-title">Unpredictable challenge</div>
            <div class="liveness-step-detail">Both client and server contribute random nonces. Their combined hash (HKDF) determines the color pattern &mdash; neither side can predict or replay it. The challenge expires after 30 seconds and can only be used once.</div>
          </div>
        </div>
        <div class="liveness-step">
          <div class="liveness-step-num">2</div>
          <div class="liveness-step-body">
            <div class="liveness-step-title">Four-quadrant color flash</div>
            <div class="liveness-step-detail">The screen flashes a <em>different color in each of four quadrants</em> across 3 rounds, with the grid boundary shifted by the challenge. A real 3D face reflects each quadrant differently across its surface; a flat photo or screen reflects them uniformly.</div>
          </div>
        </div>
        <div class="liveness-step">
          <div class="liveness-step-num">3</div>
          <div class="liveness-step-body">
            <div class="liveness-step-title">3D geometry detection</div>
            <div class="liveness-step-detail">The camera captures how light reflects off your face in each round. The server checks that adjacent regions respond <em>differently</em> to their quadrant colors, and measures how many face patches responded and how convex the response is. Those geometric cues are recorded but not yet enforced: their thresholds await a presentation-attack study.</div>
          </div>
        </div>
        <div class="liveness-step">
          <div class="liveness-step-num">4</div>
          <div class="liveness-step-body">
            <div class="liveness-step-title">ZK proof of liveness</div>
            <div class="liveness-step-detail">Quantised reflectance fingerprints enter the Halo2 circuit alongside the face match. The challenge nonces and every liveness threshold are bound into a Poseidon digest the verifier recomputes, so the proof answers this challenge only. The verifier learns a single <strong>liveness bit</strong> plus that digest &mdash; the proof itself omits raw reflectance data, but the server receives and processes it. The result screen shows that bit separately from the server's own check.</div>
          </div>
        </div>
      </div>

      <div class="privacy-note">
        Software-only camera checks are experimental presentation-attack risk reduction. A malicious prover can fabricate the witness; physical capture is not cryptographically established.
      </div>
    </div>

    <div class="card">
      <h3>Deduplication unavailable</h3>
      <p>Deterministic biometric commitments and anonymous set membership are
      unavailable. Public helper data can enable offline biometric guessing and
      matching records across services.</p>
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
          <div class="timing-label">ZK proof (~250ms)</div>
        </div>
        <div class="timing-item">
          <div class="timing-value" style="font-size: 1rem;">BN254</div>
          <div class="timing-label">Elliptic curve</div>
        </div>
      </div>
    </div>

    <div style="text-align: center; margin-top: 2rem;">
      <label for="demo-credential">Operator-issued demo credential</label>
      <input id="demo-credential" type="password" autocomplete="off" spellcheck="false" maxlength="64" />
      <p>The credential stays in this page's memory. Reloading or restarting clears it.</p>
      <p id="credential-error" role="alert"></p>
      <button class="btn btn-primary" id="start-demo" style="padding: 1rem 2rem; font-size: 1.125rem;">
        Start Interactive Demo
      </button>
    </div>
  `;
}

export function attachHomeHandlers(onStart: () => void): void {
  document.getElementById('start-demo')?.addEventListener('click', () => {
    const input = document.getElementById('demo-credential') as HTMLInputElement | null;
    try {
      setCredential(input?.value.trim() || '');
      if (input) input.value = '';
      onStart();
    } catch (error) {
      const message = document.getElementById('credential-error');
      if (message) message.textContent = error instanceof Error ? error.message : 'Invalid credential';
    }
  });
}
