# Sigma Rule Writing Guide

## Format Dasar

Sigma = YAML-based detection rule format. Vendor-neutral, bisa convert ke Splunk, Elastic, Wazuh, dll.

```yaml
title: Nama Rule (wajib, deskriptif)
id: UUID (wajib, unik, generate via `uuidgen` atau python)
status: experimental | test | stable
description: Penjelasan apa yang dideteksi (wajib, min 80 char)
author: Nama Pembuat (wajib)
date: YYYY/MM/DD
modified: YYYY/MM/DD
references:
    - URL referensi
tags:
    - attack.<tactic>      # MITRE ATT&CK tactic
    - attack.t<technique>   # MITRE ATT&CK technique ID
logsource:
    product: <product>      # windows, linux, network, cloud
    service: <service>      # auth, sysmon, powershell, etc.
detection:
    selection:              # Pattern matching
        field|modifier:     # field name + optional modifier
            - value         # value to match
    condition: selection    # Logic: selection, 1 of selection*, all of selection*
falsepositives:
    - Scenario yang bisa false positive
level: critical | high | medium | low
```

## Field Modifiers

| Modifier | Fungsi | Contoh |
|---|---|---|
| (none) | Exact match | `EventID: 4625` |
| `\|contains` | Substring match | `CommandLine\|contains: "-enc"` |
| `\|startswith` | Prefix match | `Image\|startswith: "C:\\\\Windows"` |
| `\|endswith` | Suffix match | `Image\|endswith: ".exe"` |
| `\|re` | Regex match | `url\|re: ".*\\\\.php$"` |
| `\|all` | All values must match | `field\|all: val1, val2` |
| `\|base64` | Base64 decode then match | `CommandLine\|base64: "..."` |
| `\|cidr` | CIDR network match | `src_ip\|cidr: "10.0.0.0/8"` |

## Detection Conditions

```yaml
# Single selection
condition: selection

# Multiple selections (AND)
condition: selection1 and selection2

# Multiple selections (OR)
condition: selection1 or selection2

# At least 1 match from selection group
condition: 1 of selection_*

# All must match
condition: all of selection_*

# With filter (exclude)
condition: selection and not filter

# Count-based (need timeframe)
condition: selection | count() > 5
timeframe: 5m
```

## MITRE ATT&CK Tags

```
attack.initial_access      → TA0001
attack.execution           → TA0002
attack.persistence         → TA0003
attack.privilege_escalation → TA0004
attack.defense_evasion     → TA0005
attack.credential_access   → TA0006
attack.discovery           → TA0007
attack.lateral_movement    → TA0008
attack.collection          → TA0009
attack.exfiltration        → TA0010
attack.command_and_control → TA0011
attack.impact              → TA0040
```

Technique: `attack.t<ID>`, contoh: `attack.t1059.001` (PowerShell)

Cari di: https://attack.mitre.org/

## Level Guidelines

| Level | Use When |
|---|---|
| `critical` | Ransomware, confirmed breach, active exploitation |
| `high` | Malware execution, privilege escalation, webshell |
| `medium` | Brute force, suspicious activity, recon |
| `low` | Informational, policy violation, audit |

## Status Lifecycle

```
experimental → test → stable
     ↑           ↑        ↑
  Baru dibuat   Diuji    Production-ready
```

## Contoh Rule Lengkap

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: experimental
description: >
    Detects PowerShell execution with encoded commands, which is a common
    technique used by malware and attackers to obfuscate payloads.
author: Security Team
date: 2026/07/20
modified: 2026/07/20
references:
    - https://attack.mitre.org/techniques/T1059/001/
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
