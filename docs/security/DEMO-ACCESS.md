# Restricted demo access

The API has no anonymous mode. Before starting the server, provision
`SABLE_API_CREDENTIALS` through the process environment or the deployment's secret
manager. The value is a JSON array of objects with exactly `principal` and `token`
fields. Principals must be unique identifiers of 1–64 ASCII letters, digits,
underscores or hyphens. Tokens must be independently generated 32-byte random
secrets encoded as 64 lowercase hexadecimal characters. Do not use example,
guessable or shared tokens. One to 32 principals are supported.

The operator supplies each participant their own token over a trusted channel.
The browser asks for this credential before starting the demo and keeps it only
in page memory; reload or Restart clears it. The credential is sent as a Bearer
Authorization header to protected API routes. The browser requires HTTPS, except
for loopback development, and rejects redirects. The health endpoint is public
and does not receive the token. Never place tokens in URLs, source control, static
assets or browser persistent storage. Server-side request/header logging must not
record credentials or biometric bodies.

This credential authenticates an invited demo participant, not biometric identity
or camera provenance. Request `user_id`, `principal`, session IDs, challenge IDs,
and proof metadata cannot select the authenticated principal. Every stored
enrollment, challenge, liveness result and verification policy is partitioned by
the middleware-authenticated principal. Wrong-principal requests cannot read or
consume another participant's records. Existing pre-remediation session IDs are
not credentials and must not be imported as such.

Each principal receives twelve API operations per minute, four simultaneous
enrollment records, and eight records in each challenge-related cache. Global
admission additionally allows one expensive operation at a time without a waiting
queue. The server keeps SHA-256 credential digests in its registry and clears
temporary parsed token strings; deployment environment storage is still the
operator's responsibility. Removing or changing a credential and restarting the
server revokes its old token and discards transient enrollment state. There is no
hot credential rotation API.

These controls do not make the demo production authentication. See
[the capture trust boundary](CAPTURE-TRUST-BOUNDARY.md) and
[the remediation record](REMEDIATION-2026-09-14.md).

## Logging and diagnostic data

Request handlers no longer emit per-request logs: this removes embedding statistics,
similarity/distance scores, fingerprints, reflectance deltas, photometric/glint
measurements and authentication outcomes from that logging path. Startup messages
remain. Rejection messages omit similarity, Hamming-distance and spatial scores.
Source regression tests guard these specific changes; they are not a deployment
logging audit.

Successful authenticated research responses still include diagnostic measurements.
Treat response bodies as sensitive too. Reverse proxies, host logging, browser tools,
telemetry, crash dumps and any deeper-library diagnostics remain separate audit
surfaces. This change does not provide client-only proving or hide biometrics from
the server operator.
