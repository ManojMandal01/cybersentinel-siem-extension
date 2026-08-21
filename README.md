# CyberSentinel SIEM Browser Extension

CyberSentinel is a **mini SOC + Browser EDR + Threat Intelligence Platform** for Chrome and Edge, with a modular architecture intended for controlled security labs and enterprise-policy deployments.

## Architecture

```text
Browser Event
     ↓
Normalize + Sanitize
     ↓
Collectors → Detection → Threat Intelligence
     ↓              ↓
     └──────→ Correlation / Incident ID
                     ↓
              Risk Scoring 0-100
                     ↓
             MITRE ATT&CK + Evidence
                     ↓
          IOC Generation / Alerting
              ↓             ↓
           Splunk        SOC Dashboard
```

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| Log Collection | ✅ | URL, redirects, tabs, downloads, forms, permissions, extensions |
| Detection | ✅ | Phishing, login pages, redirects, scripts, credential harvesting, malware delivery |
| Threat Intelligence | ✅ | Bounded, cached OpenPhish + URLhaus providers with health/backoff handling |
| PhishTank | ⏸️ | Disabled by default until supported automated-feed access is configured |
| AI Analysis | 🔶 Optional | Heuristic fallback + validated external AI/vision endpoint with timeouts and sanitized payloads |
| Risk Scoring | ✅ | Weighted 0-100 scoring with correlation evidence |
| Correlation | ✅ | Related browser signals grouped into incident IDs |
| MITRE ATT&CK | ✅ | Detection-to-technique mapping |
| IOC Generation | ✅ | URLs, domains, IPs and other indicators |
| STIX Export | ✅ | STIX 2.1-style IOC bundle export from the dashboard |
| Alert Engine | ✅ | Browser notifications + Discord webhook |
| Threat Hunting | ✅ | Query filters for risk, domain, incident, MITRE, state, feed, source and time |
| SIEM Integration | ✅ | Splunk HEC with timeout, sanitization and structured incident context |
| SOC Dashboard | ✅ | Executive, analyst, timeline, hunting, IOC, incident graph, settings and feed-health views |
| MITRE Heatmap | ✅ | Visual technique heatmap in the Analyst view, computed from recent event technique hits |
| IOC Explorer | ✅ | Search, type and reputation filtering over the IOC store, cross-checked against the threat cache |
| Incident Graph | ✅ | SVG relationship graph linking correlated incidents that share a domain |
| Browser Regression | ✅ | Playwright suite that loads the unpacked extension in Chromium and exercises the dashboard end-to-end |
| Security Hardening | ✅ | Sensitive telemetry sanitization, quota-safe storage, bounded feeds, deduplication and reduced permissions |

## Quick Start

### Load the extension

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the repository folder.
5. Click **Reload** after pulling a new branch revision.

### Verify the service worker

Open the extension card → **Service worker → Inspect → Console**.

A healthy initialization should produce a CyberSentinel initialization message and should not emit repeated feed errors. The dashboard's **Settings → Threat Feed Health** view also shows provider state.

### Run the browser test suite

The test runner is linked from the dashboard sidebar as **Run Tests**. It uses a local browser harness with mocked Chrome APIs and mocked feed responses; it does not crawl external repositories or download feed-provided artifacts.

For the most reliable runtime verification, load the unpacked extension first, open the dashboard, then select **Run Tests**.

### Run the Playwright regression suite

```bash
npm install
npx playwright install chromium
npm run test:browser
```

This loads the *real* unpacked extension into a persistent Chromium context (MV3 service workers require a headed browser, not Playwright's default headless mode), resolves the extension id, and exercises the dashboard: view navigation, the MITRE heatmap, the IOC Explorer filters, and the Incident Graph. It runs automatically in CI via `.github/workflows/validate.yml` under Xvfb.

## MITRE ATT&CK Heatmap

The Analyst view renders a color-graded heatmap (`src/visualization/mitre-heatmap.js`) across the known technique catalogue, intensity scaled by hit count over the most recent 500 events, with peak risk score shown per cell. Cells render at zero-hit state too, so the full catalogue is always visible.

## IOC Explorer

The IOC Table view is now a filterable explorer: free-text search over value/context, a type filter (domain/URL/IP/hash), and a reputation filter cross-checked live against the threat-intel cache (`GET_IOC_EXPLORER` in the service worker). Reputation is derived from cached feed hits, not re-fetched per keystroke.

## Incident Graph

The Incident Graph view (`src/visualization/incident-graph.js`) renders correlated incidents as nodes on a deterministic ring layout — no physics/layout dependency, so it stays CSP-safe inside the MV3 dashboard. Node size reflects event volume, color reflects peak risk, and edges connect incidents that share a domain.

## Threat-feed safety model

Threat-feed entries are treated strictly as **indicators of compromise**. CyberSentinel never follows an IOC URL to discover additional content.

In particular, the threat-feed refresh path will not download:

- GitHub/GitLab release artifacts
- ZIP/TAR/GZ/RAR/7z archives
- Executables or installers
- Arbitrary repository pages
- Feed-provided URLs for secondary crawling

Feed responses are bounded by a maximum byte size and item count, and the cached IOC set is bounded. The threat cache is stored in a dedicated IndexedDB database instead of `chrome.storage.local`, avoiding extension-storage quota failures when feeds contain large datasets.

## Splunk

In **SOC Dashboard → Settings**, enable Splunk and configure:

```text
HEC URL:    https://your-splunk:8088
Index:      cybersentinel
Sourcetype: cybersentinel:browser
```

The HEC client uses a bounded request timeout and sends structured fields including `event_id`, `incident_id`, `risk_score`, `risk_level`, MITRE technique, evidence, detections and correlation context. Telemetry is sanitized again immediately before external forwarding.

## Optional external AI

AI is disabled by default. If enabled, configure an HTTPS endpoint and API key in the dashboard.

CyberSentinel uses a tiered strategy: external AI is only invoked for suspicious/high-value events rather than every page. URL credentials, tokens, passwords and common secret assignments are sanitized before the AI request is built.

The endpoint must return a classification object such as:

```json
{
  "classification": "phishing",
  "confidence": 92,
  "signals": ["brand_impersonation", "credential_form"]
}
```

## Threat Hunting

Examples:

```text
show phishing alerts
show malicious domains
show downloads
show credential forms
show suspicious scripts
show critical alerts
show threat feed hits
show incidents
show iocs
show phishing alerts where risk>=51 and since:24h
show threat feed hits where feed:OpenPhish and since:7d
show incidents where incident_id:inc_
```

Supported filters include risk score, domain, event type, incident ID, MITRE technique, triage state, risk level, threat feed, source, and relative/absolute time constraints.

## IOC Export

Open **IOC Table → Export IOCs as STIX 2.1** to generate a JSON bundle suitable for downstream analysis or conversion into a formal STIX workflow.

## Security model

CyberSentinel intentionally **does not store credential values**. It records security-relevant facts such as the presence of a password field, while sanitizing URL credentials, tokens, OTPs, cookies, authorization values and sensitive nested telemetry before persistence or external forwarding.

Configuration endpoints are validated to use HTTP(S), embedded credentials are rejected, and configuration lists are normalized and bounded.

The extension also performs lightweight in-memory event deduplication to reduce duplicate processing and unnecessary external lookups.

## Project Structure

```text
cybersentinel-siem-extension/
├── manifest.json
├── src/
│   ├── background/                  # Orchestrator
│   ├── collectors/                  # Browser telemetry
│   ├── detection/                   # Security detectors
│   ├── intel/                       # Threat feeds + bounded threat cache
│   ├── ai/                          # Heuristic/external AI analysis
│   ├── risk/                        # Risk scoring
│   ├── correlation/                 # Incident correlation
│   ├── mitre/                       # ATT&CK mapping
│   ├── ioc/                         # IOC + STIX export
│   ├── alerts/                      # Alert lifecycle
│   ├── hunting/                     # Threat hunting queries
│   ├── siem/                        # Splunk/Elastic/Wazuh integration
│   ├── visualization/               # MITRE heatmap + incident graph rendering
│   ├── content/                     # Content script
│   └── shared/                      # Storage, schema, config validation
├── popup/                           # Quick SOC view
├── dashboard/                       # Full SOC dashboard
├── tests/                           # Mocked-Chrome browser regression suite
│   └── playwright/                  # Real-Chromium end-to-end regression suite
├── rules/phishing-rules.json
└── icons/
```

## Risk levels

| Score | Level |
|-------|-------|
| 0-25 | Low |
| 26-50 | Medium |
| 51-75 | High |
| 76-100 | Critical |

Risk can be increased by phishing, typosquatting, homographs, suspicious TLDs, credential forms, obfuscated JavaScript, malicious reputation, redirects, malware delivery, credential harvesting, AI classification, and behavioral correlation.

## Roadmap

### Completed hardening

- Versioned security-event schema
- Sensitive telemetry sanitization at storage and forwarding boundaries
- Detection/risk improvements
- Behavioral incident correlation
- Bounded threat-feed fetching and backoff/health reporting
- Threat-cache migration to dedicated IndexedDB storage
- Domain DNS/RDAP intelligence
- SOC incident triage
- Threat hunting filters and time ranges
- Splunk structured events + timeout
- Configuration validation
- STIX IOC export
- Optional AI/vision interface
- Event deduplication
- Reduced extension permissions
- Browser regression coverage

### Next release candidates

- Larger benign/malicious detection corpus and false-positive benchmarking
- More threat-intelligence providers through a provider interface
- Full incident graph visualization
- Expanded browser automation tests
- Performance profiling across large event volumes
- Enterprise deployment/policy configuration
- Optional blocking/warning mode after detection reliability is validated

## Permissions Note

The extension currently requests broad host access because its purpose is browser-wide security monitoring. For production enterprise deployment, scope `host_permissions` and content-script matches to the organization's approved domains whenever possible.

## License

MIT — use for portfolio, labs, and educational SOC projects.
