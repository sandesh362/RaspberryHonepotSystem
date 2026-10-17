# Phase 1 delivery and Phase 2 boundaries

Prepared 17 October 2026. The planned next Monday evaluation is 19 October 2026.

## Semester VII: software foundation

This delivery implements the control plane and local software demonstration. It targets the software portion of the two-semester project; a percentage of overall academic completion is an estimate for the guide, not an independently measured result.

Completed behaviors:

- Unique local analyst credentials, session expiry, protected data routes, CSRF/origin validation and device-token separation.
- Canonical event schema, UTC timestamps plus receipt time, redaction, idempotent ingest and conflicting-ID rejection.
- Durable serialized SQLite transactions, indexes, event/session/finding relationships and a hash chain.
- Actual localhost HTTP decoy and a bounded self-test with real requests.
- Versioned TCP-scan, repeated-authentication, HTTP-enumeration and command-intent rules.
- React views for overview, filtered/paginated events, sessions, findings, case evidence, lab controls, model experiment, health and roadmap.
- Authenticated resumable SSE changes and periodic state reconciliation.
- Explicit REPLAY namespace for generated scenarios and Cowrie JSON imports. LIVE and REPLAY never share counters.
- Independent case snapshots, notes/status audit, bounded background ZIP/PDF export and integrity checking.
- Deterministic Random Forest and Isolation Forest experiment on 400 generated feature samples, split into 300 training runs and 100 holdout runs.
- Windows launcher, locked packages, offline fonts, verification tool and automated tests.

## What the demonstrated features prove

An HTTP request can reach a real decoy, become a committed event, satisfy an explainable rule, appear in the UI, and be exported with verifiable bytes. Restarting the app preserves committed data. Retried identical events do not duplicate records; conflicting IDs fail and roll back the batch.

Generated SSH/scan scenarios prove software pipeline behavior, not actual network capture of SSH or SYN traffic. Cowrie imports prove adapter compatibility for supported record types, not a running Cowrie deployment.

The ML benchmark proves a training/evaluation/inference path. Generated features are deliberately easy to separate. Its score is not deployed attack accuracy; it must not be presented as such.

## Semester VIII: hardware and field validation

1. Confirm Pi model/RAM/64-bit OS; test ARM64 dependencies and resource budget.
2. Install actual Cowrie and Suricata on an isolated lab network.
3. Add file-generation/offset checkpoints, rotation handling, raw-file transfer and a durable bounded sensor spool.
4. Add pinned TLS, token lifecycle, hardware service isolation, IPv4/IPv6 firewall tests and restricted egress.
5. Confirm closed/filtered-port probe visibility on the actual capture interface.
6. Collect reviewed run/day-separated real captures; compare rules, ML and hybrid results with uncertainty.
7. Validate clock drift, data gaps, overload, retention quotas, SD wear and a 24-hour soak.
8. Expand forensic completeness to original files/transcripts/optional bounded PCAP and independently retained anchors.

These are substantial remaining engineering tasks. IoT integration is the main next-semester focus, but real-data evaluation and hardening remain too.

## Release constraints

Loopback-only, one analyst and one server worker. No TLS or production deployment claim. No automatic response/blocking, arbitrary remote scans, malware execution, internet honeypot exposure or claimed institution approval.

The Phase 1 Python backend writes directly to SQLite from the local software source with a serialized transaction lock. It does not yet implement the architecture's durable edge queue or separate export worker process. Export work runs off the request path through a bounded background task; interrupted pending jobs fail visibly on restart.

Sessions use the source session ID and sensor/mode namespace. Rule grouping additionally uses source IP and a source-time minute bucket. That is approximate correlation; NAT and minute boundaries can split or group related activity. Multi-label field modeling and confidence-based network/session correlation remain future work.
