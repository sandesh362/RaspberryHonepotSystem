# SentinelPi

Intelligent Raspberry Pi-Based Honeypot for Cyber Attack Detection, Logging and Forensic Analysis.

**Phase 1 is a working local software platform.** Raspberry Pi deployment, actual SSH/Telnet network collection, edge reliability and real-capture ML evaluation remain Phase 2. The approved architecture stays in [docs/architecture.md](docs/architecture.md).

## Start on Windows

Double-click **Start-SentinelPi.cmd** in this repository. First launch installs pinned backend dependencies, installs locked frontend dependencies and builds the UI. It then starts:

- Workspace: **http://127.0.0.1:8000**
- Local HTTP decoy: **http://127.0.0.1:9090**

The launcher prints your unique username/password. They are also stored in **data/local-credentials.json**, which is ignored by Git. Keep that file private. Leave the terminal open; Ctrl+C stops both services. No cloud account, API key or paid service is needed.

Requirements for another computer: Python 3.11+ (3.12 tested), Node.js 22 LTS (22.13 tested), and internet for first installation. After setup the local build, fonts, rules, model experiment and exports work offline. On this computer the local environment and build have already been prepared.

A quicker repeat launch after a successful build:

~~~powershell
.\tools\start.ps1 -SkipBuild
~~~

If a PowerShell policy blocks a directly invoked script, use the CMD launcher; its process-local policy argument does not change the machine policy. If port 8000 is busy, stop the existing app through its own terminal rather than killing an unknown process.

## Evaluation demo

Follow [docs/evaluation-guide.md](docs/evaluation-guide.md). Initial **Lab replay** contains 192 clearly labeled generated records, not claimed Pi telemetry. **Live software** only counts actual observations collected locally or accepted from a credentialed external collector.

1. Sign in and explain the Phase 1/Phase 2 roadmap.
2. Open Lab console and run the local HTTP test.
3. In Live software, show records, login/HTTP findings and a session timeline.
4. Run a guided replay to demonstrate SSH/scan investigation without claiming hardware deployment.
5. Create a case from a finding, add notes, export evidence and verify it.
6. Explain the synthetic model's provenance and remaining real-data validation.

## Implemented

- React/TypeScript dashboard, bundled fonts, responsive views and native accessible detail dialogs.
- FastAPI, typed request validation, bounded batches, session auth, CSRF/origin checks and a separate ingestion credential.
- SQLite WAL, serialized transactions, idempotency/conflict detection, event hash chain, session grouping and audit history.
- Actual local HTTP decoy. It responds inertly; no shell commands, SQL or downloaded code are executed.
- Explainable scan, authentication, HTTP enumeration and command-intent rules.
- Search/filter/paginated activity, resumable SSE updates, finding review and case notes.
- Cowrie JSON/JSONL imports into REPLAY only.
- Random Forest / Isolation Forest feasibility benchmark with computed synthetic holdout metrics.
- Background PDF/ZIP exports, per-file hashes and retained package-hash verification.

## Phase 1 boundaries

This is a **local research release**, not a production-certified security product. Keep the loopback binding. TLS, roles beyond one analyst, credential rotation, hard service isolation, Pi packet capture, complete raw file/PCAP acquisition, disk retention, queued edge delivery and field ML validation require further work. No automatic internet exposure or remote scanning is implemented.

The live HTTP test always targets the app's own fixed loopback decoy. Replay uses documentation IP addresses. Model scores are not probabilities that a source is malicious. A high synthetic F1 score reflects an easy generated benchmark; it is not evidence of generalization.

Credentials are redacted at collection. Exports preserve redacted records, not original unredacted Cowrie files. Hashes establish equality against a retained anchor; a privileged attacker could rewrite both data and a local anchor. Cases snapshot events at creation. Pending exports interrupted by restart fail visibly and can be requested again.

Database schema is version 1. Do not manually change it or run multiple server workers. Data volume is intentionally small; bounded requests do not constitute a retention policy. Back up data using SQLite's backup API and protect private export storage. Never commit runtime data.

## Layout

~~~text
backend/app/       API, auth, schemas, database, rules, ML, decoy, lab, evidence
backend/tests/     integration and regression tests
frontend/src/      React workspace and typed API client
tools/             Windows launcher, offline verifier, architecture generator
docs/              architecture, Phase 1 scope, evaluation guide, literature
data/              private runtime DB, credentials, model manifest, ZIPs (ignored)
~~~

## Development and validation

~~~powershell
.\.venv\Scripts\python.exe -m pytest -q
cd frontend
npm run build
npm audit
~~~

For hot reload, start the backend separately and run npm run dev in frontend/. Vite proxies /api to port 8000. The evaluation build is served by FastAPI so it needs one dashboard URL.

Show local credentials with: .\.venv\Scripts\python.exe -m backend.cli credentials

Verify an export independently:

~~~powershell
.\.venv\Scripts\python.exe tools/verify_evidence.py path-to-export.zip --expected-sha256 separately-retained-hash
~~~

Read [docs/api-and-data.md](docs/api-and-data.md) for contracts and [docs/phase-one.md](docs/phase-one.md) for completion evidence. Changes are left uncommitted for the owner to review and push.

If replay timestamps are from an earlier rehearsal and the last-hour chart is quiet, choose **Lab console / Load 1-hour replay**. This explicitly adds 192 generated REPLAY records with source times in the preceding hour. It never changes LIVE counters and does not execute network attacks. Counts accumulate across rehearsals.
