# Detection-as-Code Pipeline

Detection-as-Code pipeline untuk Wazuh SIEM menggunakan Sigma rules.

## Struktur Project

```
detection-as-code/
├── rules/              # Sigma rules (YAML)
├── scripts/            # Converter & deployer
├── tests/              # Unit tests
├── sample-logs/        # Sample log untuk testing
├── docs/               # Dokumentasi
└── .github/workflows/  # CI/CD config
```

## Quick Start

```bash
# 1. Setup virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Test rules
python scripts/test_rules.py

# 3. Convert Sigma -> Wazuh
python scripts/convert.py

# 4. Deploy ke Wazuh
export WAZUH_API_URL="https://your-wazuh:55000"
export WAZUH_API_USER="wazuh"
export WAZUH_API_PASS="your-pass"
python scripts/deploy.py
```

## Dokumentasi

Baca: `docs/complete-guide.md`
