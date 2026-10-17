# Monday evaluation: a practical demonstration script

Plan for 8-12 minutes after the literature and architecture slides. Start the application and rehearse before the examiner arrives. Keep the laptop powered and avoid updating packages on evaluation day.

## Before the presentation

1. Open the project folder and double-click Start-SentinelPi.cmd.
2. Wait for the server startup; sign in at http://127.0.0.1:8000 with the credentials shown in that terminal.
3. Confirm System health shows the local HTTP decoy online and Raspberry Pi as Phase 2.
4. Confirm Lab replay contains its clearly labeled fixture and Live software remains separately selectable.
5. Open this guide, the approved architecture and a previously verified evidence package as a fallback.
6. The live demo needs no internet after dependencies are installed. If port 9090 is occupied, resolve the conflict before the session; do not silently use replay as live data.

## Opening statement

"We are building a Raspberry Pi-based deception and forensic investigation system. In Semester VII we implemented the software control plane, a local HTTP decoy, explainable detection, a dashboard and verifiable evidence exports. Semester VIII will deploy Cowrie and Suricata on the Pi, add durable edge transport and validate the models on real captures."

## Demonstrate the scope

Open Project roadmap. Explain which features run now and which require actual hardware integration. Do not quote a completion percentage as a measured fact.

Open Overview in Lab replay. Explain that its 192 starting observations are generated fixtures processed by the actual backend. They exist to explain the interface; they are not captured attacks.

## Demonstrate an actual observation

1. Open Lab console and choose Run local HTTP test.
2. The app sends 14 actual GET requests and 6 synthetic failed logins to its own loopback HTTP decoy.
3. The workspace switches to Live software. Open Overview or Live activity.
4. Show the new records from 127.0.0.1. The source address is local because the test runs on this laptop.
5. Open Findings. Explain HTTP-001 and AUTH-001 thresholds using their saved reasons.
6. Open Timeline. Show source time, event details, provisional model estimate and linked rule findings.

Repeated demos accumulate records intentionally. Counters are persisted, not reset to a hardcoded target. A request sequence crossing a minute boundary may produce multiple sessions/findings.

## Demonstrate SSH/scan workflow as replay

In Lab console start Guided replay. Explain that these are generated scan and SSH records, not executed SSH attacks. Review the stream while the run progresses. Show a shell-session command as inert text; it cannot execute on the host. The Stop control cancels a running replay.

Optional: paste a sanitized real Cowrie JSON record into the importer. It always enters REPLAY.

## Demonstrate evidence

1. Create a case from a finding or session.
2. Add a note and save it.
3. Export evidence; wait for Ready.
4. Verify the package in the UI and download the ZIP.
5. Show manifest.json, events.jsonl, redacted-records.jsonl, report.pdf and SHA256SUMS.
6. Retain the package SHA-256 outside the app. An offline verifier is provided in tools/verify_evidence.py.
7. Explain that hashes show byte integrity against an anchor, not attacker identity or legal certification.

## Explain the intelligence experiment

Open Intelligence. Show computed per-label scores, training/holdout counts, feature importance and provenance. State clearly:

"This is a synthetic feasibility benchmark, not real-world accuracy. We implemented the ML lifecycle now. Real capture collection, independent-day validation and comparison against rules are scheduled for Semester VIII."

## Questions you should be ready for

- Why not just install Cowrie? Our contribution is the durable application pipeline, investigation UI, explainable findings, cases, evidence verification and evaluated integration.
- What is live today? Actual local HTTP traffic. SSH and scan examples are labeled replay until the real sensor is deployed.
- Why Python? Shared parsing, API, ML and reporting ecosystem. React is used for the analyst UI.
- What does the Pi add next semester? A real edge deployment with SSH/Telnet deception, packet observations and measured resource/recovery behavior.
- Can it prevent attacks? Phase 1 detects and records; it does not claim network-wide prevention.
- Is an IP an attacker identity? No. NAT, proxies and replay data prevent that conclusion.
- Can an attacker rewrite a hash? A privileged attacker could rewrite data and a local anchor. Independent retention is necessary for a stronger integrity claim.
- Does it need payment? The local core and dependencies require no paid API/service. Existing laptop/Pi and storage are reused.

## Do not claim

Do not claim that Raspberry Pi, actual Suricata/Cowrie capture, production TLS/containment, real-world ML accuracy, complete original forensic acquisition or college approval have already been completed.

If replay timestamps are from an earlier rehearsal and the last-hour chart is quiet, choose **Lab console / Load 1-hour replay**. This explicitly adds 192 generated REPLAY records with source times in the preceding hour. It never changes LIVE counters and does not execute network attacks. Counts accumulate across rehearsals.
