# Phase 1 API and data notes

Base URL: http://127.0.0.1:8000/api. API responses use no-store. The server also serves the built frontend from frontend/dist; there is no separate frontend service for the evaluation.

## Trust boundaries

Browser access uses a randomly generated local password and a hashed server-side session token in an HttpOnly, SameSite=Strict cookie. Cookies are not Secure only because this release is loopback HTTP. Every authenticated mutation requires X-CSRF-Token from the session response. Untrusted Origin and Host values are rejected.

Device ingestion uses Authorization: Bearer with the private generated sensor_token. That token does not grant browser data/export access. The server binds its events to external-sensor and LIVE, regardless of the body sensor ID. The Raspberry Pi row remains explicitly pending. Do not expose this interface outside loopback without implementing the Phase 2 transport controls.

Maximum API body: 512 KiB. Batch: 1-100 events. Event detail: 4,096 characters. Metadata: 8 KiB JSON. Query page: 1-200 events. Case: at most 2,000 selected events. PDF: first 150 records plus complete JSONL in the ZIP. At most two pending exports and one running replay. Other records are retained locally without an automatic quota in Phase 1.

## Browser routes

- POST /auth/login; GET /auth/session; POST /auth/logout.
- GET /summary?mode=LIVE or REPLAY.
- GET /events?mode=&limit=&before=&q=&protocol=&kind= and GET /events/{event_id}.
- GET /sessions?mode= and GET /sessions/{namespaced_session_key}.
- GET /findings?mode=&status= and PATCH /findings/{id} with status.
- GET /cases?mode=; POST /cases from a finding/session; PATCH /cases/{id} with notes/status.
- POST /cases/{id}/exports; GET /exports/{id}/download; GET /exports/{id}/verify.
- GET /integrity, /sensors, /system, /models, /project and /audit.
- POST /models/train retrains only the deterministic synthetic experiment.
- GET /lab/scenarios and /lab/runs; POST /lab/runs; POST /lab/runs/{id}/stop.
- POST /lab/replay-fixture explicitly adds a bounded 192-record synthetic replay fixture over the preceding hour.
- POST /lab/probe sends a fixed, bounded loopback request sequence; no target parameter exists.
- POST /imports/cowrie with records: a JSON array of supported Cowrie records; imports are REPLAY.
- GET /architecture.pdf and /openapi.json require analyst access.

SSE: GET /stream?after={cursor} emits change events with monotonic IDs. EventSource reconnects with Last-Event-ID. A browser refresh queries current state. Session expiry is rechecked on a long-lived stream. The UI batches change-triggered refreshes and also reconciles every ten seconds.

## Device routes

POST /ingest/batches with events; POST /sensors/heartbeat. Event input fields: event_id, source, timestamp (with timezone), kind, protocol, source_ip, source_port, destination_port, session_id, detail and metadata. source must be cowrie or suricata on the device route. Sensor timestamps more than five minutes ahead are rejected.

The response includes accepted/duplicate outcomes and a committed change cursor. Identical retries are idempotent. The same ID with different payload or mode is rejected as a conflict, rolling back the batch.

## Persistence and provenance

SQLite schema version 1 contains sensors, events, sessions, findings, cases, exports, audit, changes, users and auth_sessions. A transaction lock serializes all writers. JSON source/metadata is recursively redacted for credential keys. Passwords from the live HTTP form are never stored. Commands and paths remain untrusted inert data.

Each preserved redacted envelope is canonically serialized. Its record hash is SHA-256(previous_hash + canonical_envelope). Hashes chain across both namespaces in ingestion sequence. A case export may select only a subset, so it discloses that the package is not necessarily a contiguous chain.

UTC source time and control-plane receipt time are both retained. Charts use source event time in five-minute buckets; KPI counts cover all stored records in the chosen mode. Source order is not presented as guaranteed wall-clock causality.

Exports contain per-file hashes and a retained package hash in SQLite. Independent verification can compare the downloaded ZIP against a separately saved SHA-256 anchor. Credentials, captures, models and evidence stay outside Git.

## Supported Cowrie replay records

cowrie.session.connect, cowrie.session.closed, cowrie.login.failed, cowrie.login.success and cowrie.command.input. Other Cowrie event types are skipped and are not presented as supported. Source session IDs are namespaced/hashed; source_record preserves the redacted input. Full source-file acquisition and forensic transcripts remain Phase 2.
