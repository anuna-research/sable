# EXP-005: System-level information accounting for SABLE

| Field | Value |
|-------|-------|
| id | EXP-005 |
| date | 2026-09-15 |
| status | complete as an accounting framework; system probability unmeasured |
| inputs | paper accuracy table, liveness pre-pilot, EXP-004, current threat model |
| confidence | high in the probability identities; low in system estimates because joint attack data do not exist |

## Question

Can SABLE's biometric matcher, spatial PAD, rolling-shutter challenge, proof
system and protocol be assigned one information-theoretic security level?

Not from the present evidence. They can be placed in one probability model, but
their security exponents cannot be added unless the relevant *conditional*
acceptance rates are measured on the same attack distribution. Several terms
are currently unknown, and the malicious-prover model contains a path for which
a valid witness can be constructed without forging the proof.

## Acceptance event and attack branches

Let:

- `M`: the biometric relation accepts;
- `L_s`: the implemented spatial/geometric liveness relation accepts;
- `L_t`: the temporal rolling-shutter relation accepts;
- `P`: independently validated capture provenance/timing accepts;
- `K`: the proof and verifier-owned policy validate;
- `A`: the external authorization/credential policy accepts.

For a deployment that requires every component, the ordinary witness path is

```text
Accept = A and P and M and L_s and L_t and K.
```

For any fixed attack distribution `Q`, the chain rule gives

```text
Q[Accept]
  = Q[A]
  * Q[P | A]
  * Q[M | A,P]
  * Q[L_s | A,P,M]
  * Q[L_t | A,P,M,L_s]
  * Q[K | A,P,M,L_s,L_t].
```

Negative logarithms add only for these conditional probabilities. Multiplying
separately reported FAR, PAD and replay rates silently assumes independence and
usually overstates security: a high-quality replay of the enrolled subject is
simultaneously more likely to match the biometric and pass presentation checks.

A proof forgery, policy/state failure, stolen credential, or compromised capture
endpoint is an alternative attack branch rather than another conjunct. A system
bound must add those branch probabilities (or model them explicitly), for
example

```text
Pr[system compromise]
  <= Pr[valid-witness attack passes policy]
   + epsilon_proof
   + epsilon_protocol
   + Pr[credential/capture compromise].
```

## Matcher information

The 4,096-bit thermometer vector is representation width, not biometric entropy.
At a fixed threshold and attack population, the relevant one-attempt random-
impostor exponent is

```text
b_match(tau) = -log2(FMR(tau)).
```

The paper reports EER rather than a deployment FMR. At the EER operating point,
the reported thermometer results imply only the following *illustrative*
random-impostor exponents:

| Dataset/backbone | EER | `-log2(EER)` |
|------------------|----:|-------------:|
| LFW / FaceRes | 5.17% | 4.27 bits |
| CALFW / FaceRes | 19.07% | 2.39 bits |
| CPLFW / FaceRes | 27.56% | 1.86 bits |
| LFW / ArcFace | 4.07% | 4.62 bits |
| CALFW / ArcFace | 6.97% | 3.84 bits |
| CPLFW / ArcFace | 6.08% | 4.04 bits |

These are not deployment security estimates: the protocol uses sampled pairs,
each encoding's best fitted prescale, and a 1,024-dimensional FaceRes transform
that differs from the proved 512-byte path. EER also balances false accepts and
false rejects instead of selecting a security operating point. A valid estimate
requires the exact production transform and confidence bounds on FMR at the
chosen threshold, including targeted and look-alike attacks.

## Spatial PAD information

No APCER/BPCER study exists, so `Q[L_s | A,P,M]` is unknown. The five observed
phone-screen replays all failed the pre-pilot, but zero successes in five
independent Bernoulli trials would still give a one-sided 95% upper bound

```text
APCER < 1 - 0.05^(1/5) = 45.1%,
```

equivalent to only 1.15 negative-log bits. The captures were not designed as
independent population trials, so even that loose interval is illustrative.
The correct conclusion is that the current data demonstrate a mechanism, not a
PAD security exponent.

## Temporal challenge information

EXP-004 supplies a narrow combinatorial bound. For a uniform `n`-symbol RLL
challenge, response fixed independently before challenge issuance, verifier-fixed alignment,
and at most `t` Hamming errors,

```text
Pr[temporal accept]
  <= min(1, V_4(n,t) / (4 * 3^(n-1))),

V_4(n,t) = sum(i=0..t) choose(n,i) * 3^i.
```

At 12 fixed positions this is 19.435 exact guessing bits, 14.225 bits with one
error, and 10.133 bits with two. These values cannot be added to the matcher EER
exponents: they describe a different simulated attacker and no joint experiment
has measured `Pr[L_t | M,L_s]`.

If the attacker learns challenge `C` before constructing arbitrary pixels,
`H_inf(C | C)=0`; challenge entropy contributes no guessing bound. If phase is
freely selected, substring occurrence replaces fixed-position guessing. Capture
provenance and one protected timeline are prerequisites for applying the narrow
response-fixed-before-challenge bound to a deployment.

## Cryptographic and privacy information

The checked-in BN254 KZG backend has a heuristic cryptanalytic work-factor
estimate of roughly 100 bits under its assumptions. This is not a concrete event
probability or an information-theoretic factor that can be added to biometric
or PAD exponents; a soundness-advantage bound requires a reduction and an
adversary resource bound. When a malicious prover can construct a satisfying
witness, proof soundness is not attacked at all.

The deterministic public template digest `D = Poseidon(Q)` is linkable. Because
it is a deterministic function of the encoded template, it is not
information-theoretically hiding; it can reveal equality and at most one field
element (roughly 254 bits) about `Q`. Its practical preimage resistance depends
on both Poseidon and the unknown min-entropy of the biometric-template
distribution. The 4,096-bit encoding width is not a preimage-security claim.

The zero-knowledge protocol aims to reveal no witness information beyond its
public inputs under computational assumptions. The verifier still learns the
deterministic template digest, threshold, challenge digest, and accepted result
bits. An adaptive accept/reject oracle can leak additional information over
queries; request authorization, fixed policy, rate limits and audit rules are
therefore part of the privacy and guessing model. The centralized demo sees the
raw inputs and has no such verifier-privacy boundary.

## Attempts and retries

Every stated probability must name an attempt budget. If independent attempts
have success probability `p`, then

```text
Pr[success within q attempts] = 1 - (1-p)^q <= q*p.
```

Selective aborts, challenge grinding, multiple accounts and recovery flows can
increase the effective `q`. Single-use challenges prevent reuse of one proof;
they do not by themselves bound the number of fresh attempts.

## Threat-model consequence

Conditional on API authorization, under the paper's strongest capture
adversary---a prover with the enrolled template and control of all submitted
embeddings, images and liveness measurements---the attacker need not guess the
biometric or challenge and need not forge Halo2. They can construct a satisfying
witness. Without independently validated capture provenance, the overall system
has no positive information-theoretic physical-authentication exponent against
that branch.

Quantitative composition becomes meaningful under narrower deployment profiles:

1. **Precommitted replay, trusted capture:** measure matcher and PAD conditional
   rates jointly, then apply the fixed-timeline temporal bound.
2. **Physical presentation, protected capture:** estimate the joint
   `Pr[M,L_s,L_t | attack]` over prints, displays, masks and adaptive lighting.
3. **Malicious application, protected camera path:** include the capture
   attestation failure probability and bind it to the same proof transcript.
4. **Arbitrary pixels without protected capture:** report no physical-liveness
   security bound.

## Required evaluation

1. Evaluate the exact 512-byte transform at deployment thresholds and report
   FMR/FNMR confidence bounds, including targeted impostors.
2. Run the PAD study on genuine users and attack instruments, reporting joint
   biometric-plus-PAD acceptance rather than isolated APCER alone.
3. Run EXP-002 on phones and calculate temporal information from the joint
   multi-frame timeline, including errors, erasures and retries.
4. Evaluate adaptive LEDs, displays, relays and arbitrary frame injection.
5. Specify the allowed attempt budget and calculate cumulative success.
6. Treat proof soundness, protocol/state failures and endpoint compromise as
   alternative branches in the final assurance argument.
