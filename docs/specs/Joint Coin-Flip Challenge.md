# Joint Coin-Flip Challenge

The protocol by which the device comes to emit a flash pattern that neither
party could predict alone. Implemented in `demo/server/src/flash_challenge.rs`
and `demo/web/src/crypto/flashChallenge.ts`; planned in
`docs/plans/salt-derived-liveness.spl`.

1. The client commits: `POST /api/auth/challenge` carries `H(c_nonce)`.
2. The server answers with its own `s_nonce`.
3. Both derive `pattern = HKDF-SHA256(c_nonce ‖ s_nonce)` — twelve RGB colours
   (three rounds × four quadrants) and a per-round grid offset.
4. The client emits the pattern and captures a baseline frame plus one frame
   per round.
5. On `POST /api/auth/prove` the client reveals `c_nonce`; the server checks
   the commitment, recomputes the pattern, and derives the expected
   [[Delta Fingerprint]]s.

Commit-before-reveal stops either side biasing the pattern. The pattern is what
the [[Liveness Circuit]] checks the response against, and since
[[SPEC-006-geometric-liveness#REQ-119]] the circuit's digest also binds
`SHA-256(c_nonce ‖ s_nonce)`, so the proven statement names the challenge it
answers.

## What the coin flip gives, and what it does not

It gives freshness: a response has to be produced after the pattern is known,
so a recording made earlier cannot answer. It does not give provenance: the
client still controls capture. The `sable-approach-fit-v2` theory records that
distinction as `witness-prover-supplied`.
