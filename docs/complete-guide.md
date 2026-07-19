# Detection-as-Code Pipeline - Complete Guide

## Daftar Isi
1. [Apa itu Detection-as-Code?](#1-apa-itu-detection-as-code)
2. [Konsep Inti](#2-konsep-inti)
3. [Struktur Project](#3-struktur-project)
4. [Step 1: Setup Git Repo](#step-1-setup-git-repo)
5. [Step 2: Memahami Sigma Rules](#step-2-memahami-sigma-rules)
6. [Step 3: Tulis Rule Pertama](#step-3-tulis-rule-pertama)
7. [Step 4: Convert Sigma ke Wazuh Format](#step-4-convert-sigma-ke-wazuh-format)
8. [Step 5: Test Rule dengan Sample Log](#step-5-test-rule-dengan-sample-log)
9. [Step 6: Setup CI/CD dengan GitHub Actions](#step-6-setup-cicd-dengan-github-actions)
10. [Step 7: Deploy ke Wazuh](#step-7-deploy-ke-wazuh)
11. [Step 8: Monitoring & Maintenance](#step-8-monitoring--maintenance)

---

## 1. Apa itu Detection-as-Code?

### Analogi Sederhana

Bayangkan kamu bekerja di SOC (Security Operations Center). Setiap hari ada ratusan log yang masuk ke Wazuh. Kamu harus buat rules untuk deteksi serangan.

**Cara lama (Manual):**
```
1. Buka Wazuh web UI
2. Klik "Add Rule"
3. Tulis rule di text editor Wazuh
4. Save
5. Test manual
6. Kalau error, fix manual
7. Tidak ada version history
8. Kalau tim lain mau lihat, harus screenshot
```

**Cara Detection-as-Code:**
```
1. Tulis rule di file YAML (Sigma format) di laptop
2. Commit ke Git (version history auto)
3. Push ke GitHub
4. CI/CD auto-test rule (apakah rule-nya bener? false positive?)
5. CI/CD auto-convert Sigma -> Wazuh format
6. CI/CD auto-deploy ke Wazuh via API
7. Semua tim bisa lihat, review, dan kolaborasi
```

### Kenapa Penting?

| Masalah Cara Lama | Solusi DaC |
|---|---|
| Rule hilang/ketimpa | Git version history |
| Tidak ada review | Pull request review |
| Sulit test | Automated testing |
| Manual deploy | Auto deploy via API |
| Tidak konsisten | Standard Sigma format |
| Sulit share antar tim | Git repo bisa di-share |
| Tidak ada dokumentasi | Setiap rule ada metadata |

---

## 2. Konsep Inti

### Arsitektur Pipeline

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│  Developer  │────▶│   Git Repo   │────▶│  CI/CD      │────▶│  Wazuh   │
│  (Kamu)     │     │  (GitHub)    │     │  Pipeline   │     │  SIEM    │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────┘
     │                    │                    │                    │
  Tulis Sigma        Push code           Test + Convert        Deploy rules
  YAML rules         Trigger CI          Sigma -> Wazuh        Via API
```

### Alur Kerja

```
1. Kamu tulis rule Sigma (YAML) di laptop
2. Git commit + push ke GitHub
3. GitHub Actions trigger (otomatis jalan saat push)
4. Pipeline test rule (apakah syntax valid? false positive?)
5. Pipeline convert Sigma -> Wazuh rule format (XML)
6. Pipeline deploy ke Wazuh via API
7. Wazuh mulai deteksi dengan rule baru
```

### Komponen Utama

**Sigma** = Bahasa standar untuk nulis detection rules (YAML)
- Vendor-neutral: bisa convert ke Splunk, Elastic, Wazuh, dll
- Dibuat oleh Florian Roth (legend di threat intel)

**sigmac** = Tool converter Sigma -> format lain
- Python script yang baca Sigma YAML, output format target

**Wazuh** = SIEM/XDR open source
- Pakai rule format XML
- Detect via log analysis + agent monitoring

**GitHub Actions** = CI/CD platform
- Auto jalan script saat push/PR
- Free untuk public repo

---

## 3. Struktur Project

```
detection-as-code/
├── rules/                  # Folder untuk semua Sigma rules (YAML)
│   ├── auth/               # Rules untuk authentication events
│   ├── malware/            # Rules untuk malware detection
│   ├── network/            # Rules untuk network events
│   └── web/                # Rules untuk web server attacks
├── scripts/                # Python scripts untuk convert & deploy
│   ├── convert.py          # Sigma -> Wazuh converter
│   ├── deploy.py           # Deploy rules ke Wazuh via API
│   └── test_rules.py       # Test rules against sample logs
├── tests/                  # Unit tests untuk rules
│   └── test_auth_rules.py  # Test untuk auth rules
├── sample-logs/            # Sample log untuk testing rules
│   ├── auth.log            # Sample authentication log
│   └── web.log             # Sample web server log
├── docs/                   # Dokumentasi
├── .github/workflows/      # GitHub Actions CI/CD config
│   └── pipeline.yml        # Pipeline definition
├── requirements.txt        # Python dependencies
├── .gitignore              # File yang tidak di-commit ke Git
└── README.md               # Project documentation
```

### Kenapa Struktur Begini?

- **rules/** dipisah per kategori → mudah cari & kelola
- **scripts/** terpisah → logic deployment tidak bercampur dengan rules
- **tests/** → setiap rule ada test case (validasi tidak false positive)
- **sample-logs/** → log asli untuk test rule sebelum deploy
- **.github/workflows/** → config CI/CD (GitHub Actions baca folder ini)

---

## Step 1: Setup Git Repo

### 1.1 Inisialisasi Git

```bash
cd ~/Documents/project-idea/detection-as-code
git init
git branch -M main
```

**Penjelasan:**
- `git init` → inisialisasi folder jadi Git repository
- `git branch -M main` → rename branch default dari "master" ke "main" (standar modern)

### 1.2 Buat .gitignore

File `.gitignore` berguna agar file tertentu tidak ter-commit ke Git (misal: file rahasia, file sementara).

File yang akan di-ignore:
- `__pycache__/` → cache Python (auto-generated, tidak perlu di-commit)
- `*.pyc` → compiled Python (auto-generated)
- `.env` → file environment variable (berisi password/API key, JANGAN commit!)
- `venv/` → virtual environment Python
- `*.log` → file log (bisa besar, tidak perlu di-commit)
- `.vscode/` → config editor (personal preference)

### 1.3 Buat requirements.txt

File ini berisi daftar Python library yang dipal untuk project.

Library yang dipakai:
- `pyyaml` → untuk parse YAML file (Sigma rules)
- `requests` → untuk HTTP request (deploy ke Wazuh API)
- `pytest` → untuk unit testing
- `python-wazuh` → Wazuh API client (opsional, bisa pakai requests langsung)

### 1.4 Setup Python Virtual Environment

```bash
cd ~/Documents/project-idea/detection-as-code
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Kenapa Virtual Environment?**
- Setiap project punya dependency sendiri → tidak bentrok dengan project lain
- Misal: Project A butuh pyyaml v6, Project B butuh pyyaml v5 → tanpa venv akan bentrok
- `venv/` folder berisi Python + library khusus untuk project ini saja

### 1.5 First Commit

```bash
git add .
git commit -m "Initial project structure"
```

### 1.6 Push ke GitHub

```bash
# Buat repo di GitHub dulu (via web UI)
# Lalu connect lokal ke GitHub:
git remote add origin https://github.com/USERNAME/detection-as-code.git
git push -u origin main
```

---

## Step 2: Memahami Sigma Rules

### 2.1 Apa itu Sigma?

Sigma adalah format standar untuk menulis detection rules, dibuat oleh Florian Roth.

**Analogi:**
- Splunk punya SPL (Search Processing Language)
- Elastic punya Lucene query
- Wazuh punya XML rules
- Sigma = bahasa universal yang bisa convert ke semua format di atas

**Kenapa Sigma?**
- Vendor-neutral → tidak terikat 1 produk
- Human-readable → mudah dibaca (YAML)
- Machine-parsable → bisa di-convert otomatis
- Community-driven → ribuan rules sudah ada (SigmaHQ repo)

### 2.2 Struktur Sigma Rule

```yaml
title: Suspicious PowerShell Execution          # Nama rule (wajib)
id: 12345678-1234-1234-1234-123456789012       # UUID unik (wajib)
status: experimental                            # experimental/stable/test
description: Detects suspicious PowerShell...   # Penjelasan rule
author: Zulfiana Rahmi                          # Siapa yang buat
date: 2026/07/20                                # Tanggal buat
modified: 2026/07/20                            # Tanggal terakhir diubah
tags:
    - attack.execution                          # MITRE ATT&CK tag
    - attack.t1059.001                          # MITRE Technique ID
logsource:
    product: windows                            # Sumber log
    service: powershell
detection:
    selection:
        CommandLine|contains:                  # Field yang di-match
            - '-enc'                           # Suspicious flag
            - '-EncodedCommand'
            - 'DownloadString'
    condition: selection                        # Logic condition
falsepositives:
    - Legitimate admin scripts                  # Kemungkinan false positive
level: high                                     # critical/high/medium/low
```

### 2.3 Bagian-Bagian Sigma Rule

#### title
Nama rule. Harar jelas dan deskriptif.
```
GOOD: "Suspicious PowerShell Encoded Command Execution"
BAD:  "PS Rule 1"
```

#### id
UUID unik untuk setiap rule. Pakai `uuidgen` command atau online generator.
```
Kenapa penting? → Untuk tracking rule di SIEM, referensi di ticket, dll.
```

#### status
- `experimental` → baru dibuat, masih diuji
- `test` → sudah diuji tapi belum production
- `stable` → sudah production-ready

#### logsource
Dari mana log berasal?
```yaml
logsource:
    product: windows        # OS atau aplikasi
    service: powershell     # Service spesifik
    category: process_creation  # Kategori event
```

#### detection (BAGIAN PALING PENTING)
Logic deteksi. Dua bagian:
1. `selection` → pattern yang dicari di log
2. `condition` → bagaimana evaluate selection

```yaml
detection:
    selection:                    # Pattern matching
        FieldName|modifier: value
    filter:                       # Exclude (false positive reduction)
        FieldName: exclude_value
    condition: selection and not filter
```

**Modifier berguna:**
- `contains` → field mengandung string (substring match)
- `startswith` → field dimulai dengan string
- `endswith` → field diakhiri dengan string
- `re` → regex match
- `all` → semua value harus match
- `base64` → decode base64 dulu lalu match

**Condition operators:**
- `selection` → match jika selection true
- `selection and not filter` → match selection tapi bukan filter
- `selection1 or selection2` → match salah satu
- `1 of selection*` → match minimal 1 dari semua selection
- `all of selection*` → match semua selection

#### level
Prioritas rule:
- `critical` → sangat urgent (misal: ransomware detected)
- `high` → serius (misal: suspicious PowerShell)
- `medium` → mencurigakan (misal: unusual login time)
- `low` → informational (misal: user created)

#### tags
MITRE ATT&CK mapping:
- `attack.execution` → Tactic
- `attack.t1059.001` → Technique ID (PowerShell)
- `attack.t1059.004` → Technique ID (Bash)

Cari di: https://attack.mitre.org/

---

## Step 3: Tulis Rule Pertama

### 3.1 Rule: Failed Login Brute Force

Kita buat rule deteksi brute force login (banyak failed login dalam waktu singkat).

Buat file: `rules/auth/brute_force_login.yml`

```yaml
title: Multiple Failed Logins - Possible Brute Force Attack
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
    Detects multiple failed login attempts from the same source IP
    within a short time window, which may indicate a brute force attack.
author: Zulfiana Rahmi
date: 2026/07/20
modified: 2026/07/20
tags:
    - attack.credential_access
    - attack.t1110
    - attack.t1110.001
logsource:
    product: linux
    service: auth
detection:
    selection:
        message|contains:
            - 'Failed password'
            - 'authentication failure'
    timeframe: 5m
    condition: selection | count() > 5
falsepositives:
    - User forgot password
    - Misconfigured service
    - Legitimate automated scanner
level: medium
```

**Penjelasan detail:**

1. `title` → Jelas dan deskriptif
2. `id` → UUID unik (generate dengan `uuidgen` atau Python `uuid.uuid4()`)
3. `status: experimental` → Baru, masih diuji
4. `description` → Penjelasan apa yang dideteksi dan kenapa penting
5. `tags` → MITRE ATT&CK mapping (Credential Access tactic, Brute Force technique)
6. `logsource` → Log dari Linux auth service (e.g., `/var/log/auth.log`)
7. `detection.selection` → Cari log yang mengandung "Failed password" atau "authentication failure"
8. `detection.timeframe` → Window waktu 5 menit
9. `detection.condition` → Hitung jumlah match dalam 5 menit, alert jika > 5
10. `falsepositives` → Daftar kemungkinan false positive
11. `level: medium` → Prioritas menengah (bisa juga high kalau di environment sensitif)

### 3.2 Rule: PowerShell Encoded Command

Buat file: `rules/malware/powershell_encoded_command.yml`

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: experimental
description: >
    Detects PowerShell execution with encoded commands, which is a common
    technique used by malware and attackers to obfuscate payloads.
author: Zulfiana Rahmi
date: 2026/07/20
modified: 2026/07/20
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1027
logsource:
    product: windows
    service: powershell
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-e '
    filter_legitimate:
        Image|endswith:
            - '\pwsh.exe'
            - '\powershell_ise.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate admin scripts using encoding
    - Software deployment tools
level: high
```

### 3.3 Rule: Web SQL Injection Attempt

Buat file: `rules/web/sql_injection_attempt.yml`

```yaml
title: Possible SQL Injection Attempt in Web Request
id: c3d4e5f6-a7b8-9012-cdef-345678901234
status: experimental
description: >
    Detects SQL injection patterns in web server access logs,
    indicating potential database attack attempts.
author: Zulfiana Rahmi
date: 2026/07/20
modified: 2026/07/20
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    product: linux
    service: webserver
detection:
    selection:
        message|contains:
            - "' OR '1'='1"
            - "UNION SELECT"
            - "/* */"
            - "'; DROP TABLE"
            - "' OR 1=1--"
            - "xp_cmdshell"
    condition: selection
falsepositives:
    - Legitimate database admin tools
    - Security scanners (authorized)
level: high
```

---

## Step 4: Convert Sigma ke Wazuh Format

### 4.1 Install Sigma Converter

```bash
cd ~/Documents/project-idea/detection-as-code
source venv/bin/activate
pip install sigmatools
```

**Apa itu sigmac?**
- Python tool yang baca Sigma YAML → output format target (Wazuh, Splunk, Elastic, dll)
- Developed by Sigma community
- Command: `sigmac -t <target_format> -c <config> input.yml`

### 4.2 Cara Convert Manual

```bash
# Convert Sigma -> Wazuh
sigmac -t wazuh rules/auth/brute_force_login.yml
```

Output akan menjadi Wazuh rule format (XML-like).

### 4.3 Convert Script (Python)

Buat file: `scripts/convert.py`

```python
#!/usr/bin/env python3
"""
Sigma to Wazuh Rule Converter
=============================
Script ini membaca semua Sigma rules (YAML) dari folder rules/,
convert ke format Wazuh, dan simpan di folder output/.
"""

import os
import sys
import yaml
import json
import hashlib
from pathlib import Path
from datetime import datetime

# Konfigurasi path
RULES_DIR = Path(__file__).parent.parent / "rules"
OUTPUT_DIR = Path(__file__).parent.parent / "wazuh_rules"

def load_sigma_rule(file_path):
    """Baca Sigma rule dari YAML file."""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def sigma_to_wazuh(sigma_rule):
    """
    Convert Sigma rule ke Wazuh XML format.
    
    Wazuh rule format:
    <rule id="ID" level="LEVEL" ...>
        <if_sid>...</if_sid>
        <field name="...">pattern</field>
        <description>...</description>
    </rule>
    """
    
    # Generate rule ID dari hash title (Wazuh butuh numeric ID)
    rule_id = abs(hash(sigma_rule['title'])) % 100000
    
    # Map Sigma level ke Wazuh level (0-15)
    level_map = {
        'critical': 12,
        'high': 10,
        'medium': 7,
        'low': 3
    }
    wazuh_level = level_map.get(sigma_rule.get('level', 'medium'), 7)
    
    # Extract detection patterns
    detection = sigma_rule.get('detection', {})
    selection = detection.get('selection', {})
    
    # Build field matches
    fields_xml = ""
    for field, value in selection.items():
        # Clean field name (remove Sigma modifiers like |contains)
        clean_field = field.split('|')[0]
        
        # Handle list values
        if isinstance(value, list):
            for v in value:
                fields_xml += f'        <field name="{clean_field}">{v}</field>\n'
        else:
            fields_xml += f'        <field name="{clean_field}">{value}</field>\n'
    
    # Build Wazuh XML rule
    wazuh_rule = f"""
<rule id="{rule_id}" level="{wazuh_level}">
    <description>{sigma_rule['title']}</description>
    <group>{sigma_rule.get('tags', ['unknown'])[0]}</group>
{fields_xml}    <mitre>
"""
    
    # Add MITRE tags
    for tag in sigma_rule.get('tags', []):
        if tag.startswith('attack.t'):
            wazuh_rule += f'        <id>{tag.replace("attack.", "")}</id>\n'
    
    wazuh_rule += "    </mitre>\n</rule>"
    
    return wazuh_rule, rule_id

def process_all_rules():
    """Process semua Sigma rules di folder rules/."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    rules_processed = 0
    rules_failed = 0
    
    print("=" * 60)
    print("Sigma to Wazuh Rule Converter")
    print("=" * 60)
    
    # Cari semua .yml files di rules/
    for rule_file in RULES_DIR.rglob("*.yml"):
        try:
            print(f"\n[+] Processing: {rule_file.name}")
            
            # Load Sigma rule
            sigma_rule = load_sigma_rule(rule_file)
            
            # Convert ke Wazuh format
            wazuh_xml, rule_id = sigma_to_wazuh(sigma_rule)
            
            # Simpan output
            output_file = OUTPUT_DIR / f"{rule_file.stem}.xml"
            with open(output_file, 'w') as f:
                f.write(wazuh_xml)
            
            print(f"    -> ID: {rule_id}")
            print(f"    -> Level: {sigma_rule.get('level', 'medium')}")
            print(f"    -> Output: {output_file.name}")
            
            rules_processed += 1
            
        except Exception as e:
            print(f"    [ERROR] {e}")
            rules_failed += 1
    
    print("\n" + "=" * 60)
    print(f"Summary: {rules_processed} converted, {rules_failed} failed")
    print(f"Output directory: {OUTPUT_DIR}")
    print("=" * 60)
    
    return rules_processed, rules_failed

if __name__ == "__main__":
    process_all_rules()
```

**Penjelasan script:**

1. `load_sigma_rule()` → Baca YAML file, parse jadi Python dict
2. `sigma_to_wazuh()` → Convert Sigma dict ke Wazuh XML format
   - Generate numeric rule ID (Wazuh butuh angka, bukan UUID)
   - Map Sigma level (critical/high/medium/low) ke Wazuh level (0-15)
   - Extract detection patterns → Wazuh `<field>` tags
   - Add MITRE ATT&CK mapping
3. `process_all_rules()` → Loop semua .yml di rules/, convert, save ke wazuh_rules/

### 4.4 Jalankan Converter

```bash
cd ~/Documents/project-idea/detection-as-code
source venv/bin/activate
python scripts/convert.py
```

Output:
```
============================================================
Sigma to Wazuh Rule Converter
============================================================

[+] Processing: brute_force_login.yml
    -> ID: 12345
    -> Level: medium
    -> Output: brute_force_login.xml

[+] Processing: powershell_encoded_command.yml
    -> ID: 67890
    -> Level: high
    -> Output: powershell_encoded_command.xml

============================================================
Summary: 2 converted, 0 failed
Output directory: /path/to/wazuh_rules
============================================================
```

---

## Step 5: Test Rule dengan Sample Log

### 5.1 Buat Sample Log

Buat file: `sample-logs/auth.log`

```
Jan 15 10:23:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:23:05 server sshd[1235]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:08 server sshd[1236]: Failed password for invalid user test from 192.168.1.100 port 22 ssh2
Jan 15 10:23:12 server sshd[1237]: Failed password for invalid user user from 192.168.1.100 port 22 ssh2
Jan 15 10:23:15 server sshd[1238]: Failed password for invalid user guest from 192.168.1.100 port 22 ssh2
Jan 15 10:23:18 server sshd[1239]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:24:00 server sshd[1240]: Accepted password for valid_user from 10.0.0.5 port 22 ssh2
```

### 5.2 Buat Test Script

Buat file: `scripts/test_rules.py`

```python
#!/usr/bin/env python3
"""
Rule Tester
===========
Script ini test Sigma rules terhadap sample log untuk
memvalidasi apakah rule bekerja dengan benar.
"""

import re
import yaml
from pathlib import Path
from collections import defaultdict

RULES_DIR = Path(__file__).parent.parent / "rules"
SAMPLE_LOGS_DIR = Path(__file__).parent.parent / "sample-logs"

def load_sigma_rule(file_path):
    """Baca Sigma rule."""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def load_sample_log(file_path):
    """Baca sample log."""
    with open(file_path, 'r') as f:
        return f.readlines()

def test_rule_against_log(sigma_rule, log_lines):
    """
    Test Sigma rule terhadap log lines.
    Return list of matches.
    """
    detection = sigma_rule.get('detection', {})
    selection = detection.get('selection', {})
    condition = detection.get('condition', '')
    
    matches = []
    
    for i, line in enumerate(log_lines):
        line = line.strip()
        is_match = False
        
        # Check setiap field di selection
        for field, pattern in selection.items():
            clean_field = field.split('|')[0]  # Remove modifier
            modifier = field.split('|')[1] if '|' in field else 'exact'
            
            if isinstance(pattern, list):
                for p in patterns:
                    if modifier == 'contains':
                        if p.lower() in line.lower():
                            is_match = True
                            break
                    else:
                        if p == line:
                            is_match = True
                            break
            else:
                if modifier == 'contains':
                    if pattern.lower() in line.lower():
                        is_match = True
                else:
                    if pattern == line:
                        is_match = True
        
        if is_match:
            matches.append({
                'line_number': i + 1,
                'log': line,
                'rule': sigma_rule['title']
            })
    
    return matches

def run_all_tests():
    """Run test untuk semua rules."""
    print("=" * 60)
    print("Detection Rule Tester")
    print("=" * 60)
    
    total_rules = 0
    total_matches = 0
    total_no_match = 0
    
    for rule_file in RULES_DIR.rglob("*.yml"):
        print(f"\n[TEST] {rule_file.name}")
        
        try:
            sigma_rule = load_sigma_rule(rule_file)
        except Exception as e:
            print(f"  [ERROR] Cannot load rule: {e}")
            continue
        
        # Cari sample log yang sesuai
        logsource = sigma_rule.get('logsource', {})
        service = logsource.get('service', '')
        
        # Map service ke sample log file
        log_map = {
            'auth': 'auth.log',
            'webserver': 'web.log',
            'powershell': 'powershell.log',
        }
        
        log_file = SAMPLE_LOGS_DIR / log_map.get(service, 'auth.log')
        
        if not log_file.exists():
            print(f"  [SKIP] No sample log for service: {service}")
            continue
        
        # Load log
        log_lines = load_sample_log(log_file)
        
        # Test rule
        matches = test_rule_against_log(sigma_rule, log_lines)
        
        if matches:
            print(f"  [PASS] Found {len(matches)} match(es):")
            for m in matches:
                print(f"    Line {m['line_number']}: {m['log'][:80]}...")
            total_matches += len(matches)
        else:
            print(f"  [WARN] No matches found")
            total_no_match += 1
        
        total_rules += 1
    
    print("\n" + "=" * 60)
    print(f"Summary:")
    print(f"  Rules tested: {total_rules}")
    print(f"  Total matches: {total_matches}")
    print(f"  Rules with no match: {total_no_match}")
    print("=" * 60)

if __name__ == "__main__":
    run_all_tests()
```

**Penjelasan:**

1. `load_sigma_rule()` → Baca YAML
2. `load_sample_log()` → Baca sample log
3. `test_rule_against_log()` → Test 1 rule terhadap log
   - Baca selection patterns
   - Untuk setiap log line, cek apakah match dengan pattern
   - Support modifier `contains` (substring match)
   - Return list of matches
4. `run_all_tests()` → Loop semua rules, test masing-masing
   - Map Sigma logsource ke sample log file
   - Print hasil test (PASS/WARN)

### 5.3 Jalankan Test

```bash
python scripts/test_rules.py
```

Output:
```
============================================================
Detection Rule Tester
============================================================

[TEST] brute_force_login.yml
  [PASS] Found 6 match(es):
    Line 1: Jan 15 10:23:01 server sshd[1234]: Failed password for invalid user admin...
    Line 2: Jan 15 10:23:05 server sshd[1235]: Failed password for invalid user root...
    ...

Summary:
  Rules tested: 1
  Total matches: 6
  Rules with no match: 0
============================================================
```

---

## Step 6: Setup CI/CD dengan GitHub Actions

### 6.1 Buat GitHub Actions Workflow

Buat folder: `.github/workflows/`
Buat file: `.github/workflows/pipeline.yml`

```yaml
name: Detection-as-Code Pipeline

on:
  push:
    branches: [ main ]
    paths:
      - 'rules/**'              # Trigger saat rules berubah
      - 'scripts/**'            # atau scripts berubah
  pull_request:
    branches: [ main ]

jobs:
  test-and-deploy:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install pyyaml requests pytest
    
    - name: Validate Sigma Rules (YAML Syntax)
      run: |
        python -c "
        import yaml
        from pathlib import Path
        errors = []
        for f in Path('rules').rglob('*.yml'):
            try:
                with open(f) as fh:
                    yaml.safe_load(fh)
                print(f'[OK] {f}')
            except Exception as e:
                errors.append(str(f))
                print(f'[FAIL] {f}: {e}')
        if errors:
            exit(1)
        "
    
    - name: Run Rule Tests
      run: python scripts/test_rules.py
    
    - name: Convert Sigma to Wazuh
      run: python scripts/convert.py
    
    - name: Upload Wazuh Rules Artifact
      uses: actions/upload-artifact@v4
      with:
        name: wazuh-rules
        path: wazuh_rules/
    
    - name: Deploy to Wazuh (only on main)
      if: github.ref == 'refs/heads/main'
      env:
        WAZUH_API_URL: ${{ secrets.WAZUH_API_URL }}
        WAZUH_API_USER: ${{ secrets.WAZUH_API_USER }}
        WAZUH_API_PASS: ${{ secrets.WAZUH_API_PASS }}
      run: python scripts/deploy.py
```

**Penjelasan GitHub Actions:**

1. `on: push/pull_request` → Trigger saat ada push ke main atau PR
2. `paths: rules/**, scripts/**` → Hanya trigger jika file di rules/ atau scripts/ berubah
3. `jobs: test-and-deploy` → Job yang dijalankan
4. Steps:
   - `checkout` → Clone repo ke runner
   - `setup-python` → Install Python 3.11
   - `install dependencies` → Install pyyaml, requests, pytest
   - `Validate Sigma Rules` → Cek semua YAML valid (tidak ada syntax error)
   - `Run Rule Tests` → Test rules terhadap sample log
   - `Convert Sigma to Wazuh` → Convert ke Wazuh format
   - `Upload Artifact` → Simpan hasil convert (bisa di-download dari GitHub)
   - `Deploy to Wazuh` → Deploy ke Wazuh via API (hanya jika push ke main)

### 6.2 Setup GitHub Secrets

Di GitHub repo → Settings → Secrets and variables → Actions → New repository secret:

```
WAZUH_API_URL  = https://your-wazuh-server:55000
WAZUH_API_USER = wazuh-api-user
WAZUH_API_PASS = your-api-password
```

**Kenapa Secrets?**
- Password/API key TIDAK BOLEH di-commit ke Git (bisa ke-baca orang)
- GitHub Secrets → encrypted, hanya bisa dipakai di CI/CD, tidak bisa di-read setelah disimpan
- Di pipeline, akses via `${{ secrets.NAMA_SECRET }}`

---

## Step 7: Deploy ke Wazuh

### 7.1 Buat Deploy Script

Buat file: `scripts/deploy.py`

```python
#!/usr/bin/env python3
"""
Wazuh Rule Deployer
===================
Script ini deploy converted Wazuh rules ke Wazuh manager via API.
"""

import os
import sys
import requests
import urllib3
from pathlib import Path

# Suppress SSL warning (self-signed cert di lab)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Konfigurasi dari environment variable
WAZUH_API_URL = os.getenv('WAZUH_API_URL', 'https://localhost:55000')
WAZUH_API_USER = os.getenv('WAZUH_API_USER', 'wazuh')
WAZUH_API_PASS = os.getenv('WAZUH_API_PASS', 'wazuh')

RULES_DIR = Path(__file__).parent.parent / "wazuh_rules"

class WazuhDeployer:
    def __init__(self):
        self.api_url = WAZUH_API_URL
        self.session = requests.Session()
        self.session.verify = False  # Lab only! Production: pakai proper cert
        self.token = None
    
    def authenticate(self):
        """Login ke Wazuh API dan dapatkan JWT token."""
        url = f"{self.api_url}/security/user/authenticate"
        try:
            resp = self.session.post(
                url,
                auth=(WAZUH_API_USER, WAZUH_API_PASS)
            )
            if resp.status_code == 200:
                self.token = resp.json()['data']['token']
                self.session.headers['Authorization'] = f'Bearer {self.token}'
                print("[+] Authenticated to Wazuh API")
                return True
            else:
                print(f"[-] Auth failed: {resp.status_code}")
                return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False
    
    def deploy_rules(self):
        """Deploy semua rules ke Wazuh."""
        if not self.token:
            print("[-] Not authenticated. Call authenticate() first.")
            return False
        
        rules_deployed = 0
        rules_failed = 0
        
        for rule_file in RULES_DIR.glob("*.xml"):
            try:
                print(f"\n[+] Deploying: {rule_file.name}")
                
                # Baca rule content
                with open(rule_file, 'r') as f:
                    rule_content = f.read()
                
                # Deploy via API (endpoint: /rules)
                # Note: Endpoint bisa berbeda tergantung versi Wazuh
                # Ini contoh untuk Wazuh 4.x
                url = f"{self.api_url}/rules"
                
                resp = self.session.post(
                    url,
                    json={"rule": rule_content}
                )
                
                if resp.status_code == 200:
                    print(f"    [OK] Deployed successfully")
                    rules_deployed += 1
                else:
                    print(f"    [FAIL] {resp.status_code}: {resp.text}")
                    rules_failed += 1
                    
            except Exception as e:
                print(f"    [ERROR] {e}")
                rules_failed += 1
        
        print(f"\n{'='*50}")
        print(f"Deploy Summary: {rules_deployed} ok, {rules_failed} failed")
        print(f"{'='*50}")
        
        return rules_failed == 0
    
    def restart_manager(self):
        """Restart Wazuh manager agar rules baru aktif."""
        url = f"{self.api_url}/manager/restart"
        try:
            resp = self.session.put(url)
            if resp.status_code == 200:
                print("[+] Wazuh manager restarting...")
                return True
            else:
                print(f"[-] Restart failed: {resp.status_code}")
                return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False

def main():
    print("=" * 50)
    print("Wazuh Rule Deployer")
    print("=" * 50)
    
    deployer = WazuhDeployer()
    
    # Step 1: Authenticate
    if not deployer.authenticate():
        print("[-] Cannot authenticate. Check API credentials.")
        sys.exit(1)
    
    # Step 2: Deploy rules
    deployer.deploy_rules()
    
    # Step 3: Restart manager
    deployer.restart_manager()
    
    print("\n[+] Done!")

if __name__ == "__main__":
    main()
```

**Penjelasan script deploy:**

1. `WazuhDeployer` class →封装 deploy logic
2. `authenticate()` → Login ke Wazuh API, dapat JWT token
3. `deploy_rules()` → Loop semua XML rule, POST ke Wazuh API
4. `restart_manager()` → Restart Wazuh agar rules baru dimuat
5. Credentials dari environment variable → tidak hard-coded (aman)

### 7.2 Test Deploy Manual

```bash
# Set environment variable
export WAZUH_API_URL="https://your-wazuh-ip:55000"
export WAZUH_API_USER="wazuh"
export WAZUH_API_PASS="your-password"

# Run deploy
python scripts/deploy.py
```

---

## Step 8: Monitoring & Maintenance

### 8.1 Dashboard Monitoring

Monitor rule effectiveness di Wazuh:
- **Alerts triggered** → Berapa kali rule ini trigger alert?
- **False positive rate** → Berapa persen alert yang false positive?
- **Rule coverage** → Berapa banyak MITRE techniques yang sudah ter-cover?

### 8.2 Rule Lifecycle

```
1. Create rule (experimental)
     ↓
2. Test against sample log
     ↓
3. Deploy ke lab Wazuh
     ↓
4. Monitor false positive (1-2 minggu)
     ↓
5. Tune rule (adjust threshold, add filter)
     ↓
6. Status -> stable (production ready)
     ↓
7. Periodic review (setiap 3-6 bulan)
     ↓
8. Retire jika tidak relevan lagi
```

### 8.3 Best Practices

1. **Satu rule = satu file** → mudah track di Git
2. **Selalu isi falsepositives** → bantu analyst tuning
3. **Map MITRE ATT&CK** → untuk coverage tracking
4. **Test sebelum deploy** → jangan deploy rule untested
5. **Review periodik** → threat landscape berubah, rule harus update
6. **Version everything** → Git commit untuk setiap perubahan
7. **Document why** → kenapa rule ini dibuat? scenario apa?
8. **Naming convention** → `category_technique_description.yml`
9. **Unique ID** → jangan reuse UUID
10. **Tuning log** → catat perubahan rule di commit message

---

## Quick Reference

### Sigma Rule Template
```yaml
title: <DESCRIPTIVE_TITLE>
id: <UUID>
status: experimental
description: <WHAT_AND_WHY>
author: <NAME>
date: YYYY/MM/DD
modified: YYYY/MM/DD
tags:
    - attack.<tactic>
    - attack.t<technique>
logsource:
    product: <product>
    service: <service>
detection:
    selection:
        <field>|<modifier>:
            - <value>
    condition: selection
falsepositives:
    - <fp1>
    - <fp2>
level: <critical|high|medium|low>
```

### Common Sigma Modifiers
| Modifier | Fungsi | Contoh |
|---|---|---|
| contains | Substring match | `message\|contains: "Failed"` |
| startswith | Match awal string | `Image\|startswith: "C:\\\\Windows"` |
| endswith | Match akhir string | `Image\|endswith: ".exe"` |
| re | Regex match | `url\|re: ".*\\\\.php$"` |
| all | Semua harus match | `all of selection*` |

### MITRE ATT&CK Quick Reference
| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing | T1566 |
| Execution | PowerShell | T1059.001 |
| Persistence | Scheduled Task | T1053 |
| Credential Access | Brute Force | T1110 |
| Defense Evasion | Obfuscated Files | T1027 |
| Lateral Movement | RDP | T1021.001 |
| Exfiltration | Exfil over C2 | T1041 |

---

## Next Steps

Setelah pipeline jalan, bisa lanjut:

1. **Tambah lebih banyak rules** → dari SigmaHQ community repo
2. **Integrasi Threat Intel** → auto-enrich IOC di rules
3. **Auto-tuning** → ML untuk suggest threshold adjustment
4. **Rule coverage dashboard** → visualisasi MITRE ATT&CK coverage
5. **Multi-SIEM support** → convert Sigma ke Splunk/Elastic juga
6. **Alert fatigue reduction** → auto-suppress known false positives
