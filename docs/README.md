# Detection-as-Code Pipeline

> **Project Type:** Blue Team / Detection Engineering  
> **Tech:** Sigma Rules + Python + GitHub Actions  
> **Status:** Production Ready  
> **Last Updated:** 2026-07-20  

---

## What Is This?

Pipeline otomatis untuk mengelola detection rules (Sigma) dengan prinsip **Infrastructure as Code** — rules ditulis sebagai YAML, di-version di Git, auto-test, auto-convert ke format Wazuh, dan auto-deploy via CI/CD.

**Tanpa ini:** Security analyst tulis rule manual di Wazuh UI, tidak ada version history, tidak ada testing, tidak ada review.

**Dengan ini:** Tulis rule → git push → CI/CD auto-test → auto-convert → siap deploy.

---

## Project Structure

```
detection-as-code/
├── rules/                          # Sigma detection rules (YAML)
│   ├── auth/                       # Authentication-related rules
│   ├── malware/                    # Malware detection rules
│   ├── web/                        # Web attack rules
│   ├── threat_intel/               # Threat intel-based rules
│   ├── network/                    # Network detection rules
│   └── cloud/                      # Cloud detection rules
├── scripts/                        # Python automation scripts
│   ├── test_rules.py               # Test rules against sample logs
│   ├── convert.py                  # Sigma → Wazuh XML converter
│   ├── deploy.py                   # Deploy rules to Wazuh via API
│   ├── coverage.py                 # MITRE ATT&CK coverage report
│   └── quality_check.py            # Rule quality scoring
├── tests/                          # Unit tests (future)
├── sample-logs/                    # Sample logs for rule testing
├── docs/                           # Documentation & reports
├── .github/workflows/              # CI/CD pipeline config
│   └── pipeline.yml
├── requirements.txt                # Python dependencies
├── .gitignore                      # Git ignore rules
└── README.md                       # This file
```

---

## Quick Start

```bash
# 1. Clone repo
git clone https://github.com/sasuke404/detection-as-code.git
cd detection-as-code

# 2. Setup Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Run local tests
python scripts/test_rules.py

# 4. Generate coverage report
python scripts/coverage.py

# 5. Check rule quality
python scripts/quality_check.py

# 6. Convert rules to Wazuh format
python scripts/convert.py
```

---

## CI/CD Pipeline Flow

```
git push → GitHub Actions trigger
    │
    ├── Step 1: Validate YAML syntax
    ├── Step 2: Test rules against sample logs
    ├── Step 3: Generate MITRE ATT&CK coverage report
    ├── Step 4: Check rule quality score
    ├── Step 5: Convert Sigma → Wazuh XML
    └── Step 6: Upload artifacts (reports + rules)
```

**Pipeline runs on:**
- Push to `main` branch (when `rules/` or `scripts/` changes)
- Pull Request to `main`
- Manual trigger (`workflow_dispatch`)

---

## Available Sigma Rules (7)

### Authentication
| Rule | Level | MITRE |
|---|---|---|
| Brute Force Login Detection | medium | T1110 |

### Malware
| Rule | Level | MITRE |
|---|---|---|
| PowerShell Encoded Command | high | T1059.001 |

### Web
| Rule | Level | MITRE |
|---|---|---|
| SQL Injection Attempt | high | T1190 |

### Threat Intelligence (CISA Alerts)
| Rule | Level | MITRE | Source |
|---|---|---|---|
| Router Compromise (AA26-194A) | critical | T1098 | CISA Alert |
| Router LoLBins Persistence | high | T1098, T1070 | CISA Alert |
| SharePoint Web Shell Upload | critical | T1190, T1505.003 | CISA Alert |
| Salt Typhoon Telecom Recon | high | T1046 | CISA Alert |

---

## MITRE ATT&CK Coverage

| Tactic | Covered |
|---|---|
| Initial Access | ✅ 2 rules |
| Execution | ✅ 1 rule |
| Persistence | ✅ 3 rules |
| Defense Evasion | ✅ 2 rules |
| Credential Access | ✅ 1 rule |
| Discovery | ✅ 1 rule |

Run `python scripts/coverage.py` for full report.

---

## Rule Quality Scoring

Setiap rule di-score 0-100 berdasarkan:
- Metadata completeness (30%)
- MITRE ATT&CK mapping (25%)
- False positive documentation (15%)
- Description quality (10%)
- References (10%)
- Status maturity (10%)

Run `python scripts/quality_check.py` for full report.

---

## Adding New Rules

1. Create `.yml` file in `rules/<category>/`
2. Follow Sigma format (see template below)
3. Add sample log to `sample-logs/`
4. `python scripts/test_rules.py` to verify
5. `git add && git commit && git push`
6. CI/CD auto-validates

### Sigma Rule Template

```yaml
title: Descriptive Rule Name
id: <UUID>
status: experimental
description: What this detects and why it matters
author: Your Name
date: YYYY/MM/DD
references:
    - https://source-of-threat-intel.com
tags:
    - attack.<tactic>
    - attack.t<technique>
logsource:
    product: <windows|linux|network>
    service: <service_name>
detection:
    selection:
        field|modifier:
            - value_to_match
    condition: selection
falsepositives:
    - Possible false positive scenario
level: <critical|high|medium|low>
```

---

## Tech Stack

- **Sigma** — Vendor-neutral detection rule format
- **Python** — Script automation (YAML parsing, conversion, testing)
- **GitHub Actions** — CI/CD pipeline
- **Wazuh** — Target SIEM (XML rule format)

---

## Future Roadmap

- [ ] Auto-deploy to Wazuh via API
- [ ] Multi-SIEM support (Splunk, Elastic)
- [ ] Integration with SigmaHQ community rules
- [ ] Slack/Teams notification on pipeline completion
- [ ] Auto-tuning based on false positive rate
