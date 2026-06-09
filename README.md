# CyberSentinel SIEM Browser Extension

A browser extension that acts as a **mini SOC + Browser EDR + Threat Intelligence Platform** for Chrome, Edge, and Firefox.

## Architecture

```text
Browser Extension → Log Collection → Detection Engine → Alerting / IOC Gen → Splunk / SIEM → SOC Dashboard
```

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| Log Collection Engine | ✅ MVP | URL, redirects, tabs, downloads, forms, permissions, extensions |
| Detection Engine | ✅ MVP | Phishing, login pages, redirects, scripts, credential harvesting, malware delivery |
| Threat Intelligence | ✅ MVP | OpenPhish feed integration (cached) |
| AI Analysis Engine | 🔶 Heuristic | Heuristic AI + pluggable external AI endpoint |
| Risk Scoring Engine | ✅ | Weighted 0–100 scoring with Low/Medium/High/Critical |
| MITRE ATT&CK Mapping | ✅ | Auto-maps detections to T1566, T1059, T1027, T1056, T1105 |
| IOC Generator | ✅ | URLs, domains, IPs, filenames from events |
| Alert Engine | ✅ | Browser notifications + Discord webhook |
| Threat Hunting | ✅ | Natural query interface (`show phishing alerts`) |
| SIEM Integration | ✅ MVP | Splunk HEC (+ Elastic/Wazuh stubs) |
| SOC Dashboard | ✅ | Executive, analyst, timeline, hunting, IOC views |

## Quick Start

### 1. Load the extension (Chrome / Edge)

1. Open `chrome://extensions` or `edge://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `cybersentinel-siem-extension` folder

### 2. Configure Splunk (optional)

1. Open the extension popup → **Settings** (or SOC Dashboard → Settings)
2. Enable Splunk and enter your HEC URL + token:
   - HEC URL: `https://your-splunk:8088`
   - Index: `cybersentinel`
   - Sourcetype: `cybersentinel:browser`

Example Splunk event:

```json
{
  "event_type": "phishing_detected",
  "risk_score": 95,
  "technique": "T1566",
  "domain": "microsoft-secure-login.xyz"
}
```

### 3. Test phishing detection

Visit or simulate suspicious URLs (in a safe lab environment):

- `paypaI.com` patterns (homograph)
- `g00gle.com` (character substitution)
- `login-office365-secure.xyz` (brand impersonation + suspicious TLD)

## Threat Hunting Queries

```text
show phishing alerts
show malicious domains
show downloads
show credential forms
show suspicious scripts
show critical alerts
show threat feed hits
show iocs
```

## Project Structure

```text
cybersentinel-siem-extension/
├── manifest.json
├── src/
│   ├── background/service-worker.js   # Orchestrator
│   ├── collectors/                    # Module 1
│   ├── detection/                     # Module 2
│   ├── intel/                         # Module 3
│   ├── ai/                            # Module 4
│   ├── risk/                          # Module 5
│   ├── mitre/                         # Module 6
│   ├── ioc/                           # Module 7
│   ├── alerts/                        # Module 8
│   ├── hunting/                       # Module 9
│   ├── siem/                          # Module 10
│   ├── content/content-script.js
│   └── shared/
├── popup/                             # Quick SOC view
├── dashboard/                         # Full SOC dashboard
├── rules/phishing-rules.json
└── icons/
```

## Risk Scoring

| Factor | Weight |
|--------|--------|
| Suspicious Domain | 25 |
| Login Form | 20 |
| Obfuscated JS | 30 |
| Malicious Reputation | 25 |
| Typosquatting | 30 |
| Homograph | 35 |

| Score | Level |
|-------|-------|
| 0–25 | Low |
| 26–50 | Medium |
| 51–75 | High |
| 76–100 | Critical |

## Incremental Roadmap

**Phase 1 (current):** URL monitoring, phishing detection, Splunk integration, SOC dashboard

**Phase 2:** AbuseIPDB + AlienVault OTX feeds, behavior baseline, screenshot capture

**Phase 3:** External AI/vision API, email alerts, domain age API (WHOIS)

**Phase 4:** Firefox-specific build, extension blocking, enterprise policy deployment

## Resume Highlights

- Browser EDR with real-time log collection
- Rule + heuristic phishing detection with MITRE mapping
- Threat intelligence feed integration
- Risk scoring and IOC auto-generation
- Splunk HEC SIEM forwarding
- SOC analyst dashboard + threat hunting CLI

## Permissions Note

The extension requests broad host access for security monitoring. For production deployment, scope `host_permissions` to your organization's domains and publish via enterprise policy.

## License

MIT — use for portfolio, labs, and educational SOC projects.
