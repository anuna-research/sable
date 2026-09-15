#!/bin/sh
# Deliberate release hold, not an audit or an automatically inferred approval.
# Remove only through reviewed code change after requirement-by-requirement
# reassessment of docs/security/RED-TEAM-FINDINGS-2026-09-14.md.
# No environment variable or command-line bypass is supported.
printf '%s\n' \
  'SECURITY RELEASE BLOCKED: critical/high remediation is incomplete.' \
  'Local research builds are permitted; this is not production approval.' \
  'See docs/security/REMEDIATION-2026-09-14.md for evidence and outstanding gates.' >&2
exit 1
