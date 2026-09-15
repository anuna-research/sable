# Current capture and privacy boundary

The browser is an untrusted source of embeddings, images and measurements. The
server derives flash expectations from a fresh challenge, checks supplied images,
and proves relations among supplied values. There is no authenticated camera,
hardware-backed capture key, platform attestation or verifier-controlled sensor.
A malicious prover with an enrolled template can construct satisfying witnesses
without capturing a person. The proof certifies the circuit relation only.

Software-only camera liveness is presentation-attack risk reduction, not a
cryptographic proof of physical capture. Its effectiveness requires measured
presentation-attack results; a successful demonstration is not such a study.
This demo must not grant real-world authentication privileges from these proofs.

## Device-independent scope

Product decision (2026-09-15): SABLE does not bake in a device, sensor, attestation
provider or trust authority. Authenticating capture provenance is a separate
integration concern, not an assumption or guarantee of the proof system.
Selecting a platform is therefore not a prerequisite for core remediation.

The core verifier checks the circuit relation against verifier-owned policy.
Acceptance means the supplied witness satisfies that statement, not that a camera
observed a live person. Required liveness constraints remain mandatory; this
separation does not permit omitted witnesses, synthetic server fallbacks or
attacker-selected verification policy.

An application needing physical-capture assurance must independently validate its
capture evidence and authorize the result. It must bind that evidence to the same
challenge, template, measurements, capture/model policy and validity window as the
proof. That integration owns its device/trust policy and assessment. An arbitrary
client signature or user-supplied attestation verdict does not establish provenance.
No permissive default attestation provider or trusted-device assumption is added.

## Centralized demo data handling

Enrollment sends a 1024-element embedding to the server. Authentication sends a
live embedding, four frames and any enabled eye crops. The server holds enrolled
embeddings and matcher templates in process memory for at most 15 minutes
of lookup availability; periodic eviction runs every five seconds. Copies used by
active requests can outlive the cache entry until those requests finish. Enrollment
copies zeroize their embedding and matcher-template buffers on drop. Converted
feature vectors are request-local, not retained in enrollment records. Enrollment
moves its supplied embedding into the record, and authentication borrows the live
embedding instead of cloning it. The unused Pedersen
opening salt is no longer retained in session state, and feature previews are no
longer returned to the browser.

Zeroization and TTLs do not protect against an operator, a compromised server,
transport termination, request-body logging, core dumps or copies made by parsers
and image decoders. This is not end-to-end biometric privacy. Additional sensitive
data and availability controls remain tracked in the remediation record.

Client-side feature conversion, extraction and proving remain required before
claiming that biometric data stays on the user's device. A future server interface
should accept registered commitments and verifier-approved proofs only.
