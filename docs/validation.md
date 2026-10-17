# Phase 1 validation record

Validation date: 17 October 2026. Host: Windows, Python 3.12.14 and Node.js 22.13.0. This record covers the local software release, not the Raspberry Pi.

## Automated checks

- 12 backend integration/regression tests passed.
- Covered authentication/CSRF/origin/Host rejection, idempotent batches, conflicting-ID rollback, namespace binding, rule thresholds, repeated-port probe handling, redaction, pagination, evidence tampering, restart persistence, live loopback traffic, synthetic model reproducibility, concurrent WAL-file retirement, replay-fixture isolation, body-size limits and sensor-clock rejection.
- TypeScript compilation and Vite production build passed.
- Full npm audit reported zero known vulnerabilities at validation time.
- pip check reported no broken requirements.
- Original architecture PDF was left unchanged.

## Running-server checks

- Started the corrected server through tools/start.ps1 -SkipBuild -NoBrowser.
- A browser-triggered test collected 20 actual local HTTP observations and generated HTTP-001 / AUTH-001 findings.
- Verified authenticated API responses, monotonic SSE change IDs and reconnection using Last-Event-ID against the actual HTTP server.
- Created a case in the browser, saved notes, exported its ZIP/PDF and verified its retained package hash.
- Independently verified the same ZIP with tools/verify_evidence.py.
- Rendered and visually checked the generated two-page report; corrected a record split across pages.
- Exercised a paced replay, Stop, explicit one-hour replay loading, event search, protocol filtering, session/event detail and sensor health.
- Checked the 1440px desktop layout and 375px mobile layout, including the mobile menu and document-width overflow.
- Current browser error log was empty after the final application restart.

## Boundaries

These are functional checks, not a completed load/security certification. The 50 events/second target, Pi resource budget, 24-hour soak, TLS, hard host isolation, raw file acquisition, disk retention and real-capture ML performance remain unverified Phase 2 work. The current synthetic benchmark's macro-F1 is 1.000 on its deliberately separable generator; this is explicitly not field detection accuracy.

One upstream TestClient deprecation warning remains: Starlette currently warns about its httpx adapter. It did not fail any checks.

Source changes are deliberately left uncommitted; no Phase 1 branch, commit, push or PR was created.
