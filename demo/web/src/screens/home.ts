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
      <h3>How Zero-Knowledge Proofs Work</h3>
      <p>
        Imagine proving you know a password without ever showing the password itself.
        Zero-knowledge proofs (ZKPs) make this possible for biometric data:
      </p>
      <ul style="margin: 1rem 0; padding-left: 1.5rem; color: var(--text-secondary);">
        <li style="margin-bottom: 0.5rem;">
          <strong>Enrollment:</strong> Your biometric features are hashed and committed
          using Poseidon hash and Pedersen commitments
        </li>
        <li style="margin-bottom: 0.5rem;">
          <strong>Authentication:</strong> A Groth16 proof demonstrates your live scan
          matches the enrolled template
        </li>
        <li style="margin-bottom: 0.5rem;">
          <strong>Verification:</strong> The verifier learns only that you passed -
          nothing about your actual biometrics
        </li>
      </ul>
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
          <div class="timing-label">Hiding commitment (~140μs)</div>
        </div>
        <div class="timing-item">
          <div class="timing-value" style="font-size: 1rem;">Groth16</div>
          <div class="timing-label">ZK proof (~850ms)</div>
        </div>
        <div class="timing-item">
          <div class="timing-value" style="font-size: 1rem;">BLS12-381</div>
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
