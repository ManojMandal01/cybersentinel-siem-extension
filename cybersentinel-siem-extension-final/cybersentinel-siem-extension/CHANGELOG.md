# Changelog

All notable changes to this project are documented here.

## [0.3.0] - 2026-08-21

### Added
- MITRE ATT&CK heatmap in the Analyst view (`src/visualization/mitre-heatmap.js`), computed from recent event technique hits with a 0-4 intensity scale and peak-risk annotation per technique.
- Incident relationship graph (`src/visualization/incident-graph.js`): correlated incidents rendered as nodes on a deterministic ring layout, edges linking incidents that share a domain.
- IOC Explorer: free-text search plus type and reputation filters over the IOC store, cross-checked live against the threat-intel cache (`GET_IOC_EXPLORER` message handler).
- Playwright browser regression suite (`tests/playwright/`) that loads the real unpacked extension into a persistent Chromium context and exercises dashboard navigation, the heatmap, the IOC Explorer, and the incident graph.
- CI job (`browser-regression`) running the Playwright suite under Xvfb on every push/PR.
- Restyled SOC dashboard: dark graphite/amber signal palette, monospace data typography, chevron-tagged risk badges, radar-pulse live indicator. Same HTML structure, new visual design system.
- `LICENSE`, `.gitattributes` (enforces LF line endings going forward).

### Changed
- `manifest.json` and `package.json` versions aligned at 0.3.0.

### Fixed
- Normalized all text files to LF line endings (previous CRLF/LF mixing produced noisy, unreviewable diffs).

## [0.2.3] - prior baseline

Initial hardened baseline: log collection, detection engine, threat intelligence (OpenPhish/URLhaus), risk scoring, correlation engine, MITRE mapping, IOC generation, STIX 2.1 export, alert engine, threat hunting, Splunk HEC integration, mocked-Chrome browser regression suite, security hardening (sanitization, bounded feeds, reduced permissions).
