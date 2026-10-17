# Literature and technology review for the Phase 1 evaluation

This is a concise starting point for presentation slides, not an exhaustive systematic review. Read each source before quoting it. Separate published capabilities from our own prototype results.

## 1. Honeypot architecture and evasion

Niclas Ilg et al., "A survey of contemporary open-source honeypots, frameworks, and tools," Journal of Network and Computer Applications, volume 220, article 103737, 2023. DOI: https://doi.org/10.1016/j.jnca.2023.103737

The survey discusses open-source honeypot architecture, logging, deployment and detection/evasion. It supports deliberate selection of interaction level. Our project uses an emulated-shell approach rather than executing attacker commands on a real backend. It does not claim to solve honeypot fingerprinting.

## 2. Application-level SSH/Telnet observations

Cowrie official overview: https://docs.cowrie.org/en/stable/README.html
Installation: https://docs.cowrie.org/en/stable/INSTALL.html
Event vocabulary: https://docs.cowrie.org/en/stable/OUTPUT.html

Cowrie provides emulated interaction and structured logging. Phase 1 supports a subset of its JSON event vocabulary as replay imports. Actual network deployment is scheduled for Phase 2. Cowrie is credited as a dependency, not student-authored software.

## 3. Network context beyond completed logins

Suricata EVE JSON: https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-output.html
Nmap port states: https://nmap.org/book/man-port-scanning-basics.html

A completed application login is not required for network probing. The architecture therefore adds passive observations directed at the Pi. Phase 1 tests the scan-rule logic with generated records; it does not yet capture SYN packets on this Windows laptop.

## 4. Lightweight intelligence and evaluation

Random Forest implementation: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
Isolation Forest implementation: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
Leakage and preprocessing: https://scikit-learn.org/stable/common_pitfalls.html

Use a supervised primary-behavior label separately from a novelty score. Phase 1 supplies a reproducible synthetic feasibility experiment and reports its actual holdout metrics. The research question for Phase 2 is whether ML improves detection over the same rules on independent real collection runs.

## 5. Evidence-oriented investigation

NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response: https://csrc.nist.gov/pubs/sp/800/86/final

Collection, examination, analysis and reporting motivate our case workflow. Phase 1 adds redacted records, notes, manifests, checksums and verification. It does not claim legal admissibility, full forensic acquisition or NIST certification.

## Proposed project contribution

A resource-conscious edge-to-evidence workflow connecting decoy and network observations to explainable detection, live investigation and verifiable case exports. Existing honeypots, web frameworks and ML algorithms are building blocks. Student contributions are the application integration, event contracts, correlation/rules, investigation workflow, test/evaluation protocol and later Raspberry Pi validation.

## Suggested literature slide structure

- Problem: application logs alone omit probes; raw logs are hard to investigate.
- Existing work: honeypot interaction, network context, lightweight ML and forensic workflow.
- Gap addressed: an integrated portable investigation workflow with explicit provenance.
- Phase 1 evidence: working software demo and documented tests.
- Phase 2 evaluation: actual Pi capture, real dataset and measured resource/recovery behavior.

The original abstract also lists other papers. Those entries have not all been independently verified; do not copy them into a final bibliography without checking their publisher records.
