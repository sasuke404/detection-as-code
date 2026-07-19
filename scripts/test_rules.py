#!/usr/bin/env python3
"""
Rule Tester
===========
Test Sigma rules terhadap sample log untuk validasi
apakah rule bekerja dengan benar sebelum deploy.
"""

import re
import yaml
from pathlib import Path
from collections import defaultdict

RULES_DIR = Path(__file__).parent.parent / "rules"
SAMPLE_LOGS_DIR = Path(__file__).parent.parent / "sample-logs"

# Map Sigma service -> sample log file
LOG_MAP = {
    'auth': 'auth.log',
    'webserver': 'web.log',
    'powershell': 'powershell.log',
    'iis': 'sharepoint.log',
    'router': 'router.log',
    'firewall': 'firewall.log',
}


def load_sigma_rule(file_path):
    """Baca Sigma rule dari YAML."""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def load_sample_log(file_path):
    """Baca sample log, return list of lines."""
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def check_match(line, field, pattern, modifier):
    """
    Cek apakah satu log line match dengan satu pattern.

    Args:
        line: log line string
        field: nama field di Sigma (e.g. 'message')
        pattern: nilai yang dicari
        modifier: 'contains', 'startswith', 'endswith', 'exact'

    Returns:
        bool: True jika match
    """
    if modifier == 'contains':
        return pattern.lower() in line.lower()
    elif modifier == 'startswith':
        return line.lower().startswith(pattern.lower())
    elif modifier == 'endswith':
        return line.lower().endswith(pattern.lower())
    else:
        return pattern.lower() == line.lower()


def line_matches_keyword(line, patterns):
    """Cek apakah line mengandung salah satu pattern (contains, case-insensitive)."""
    if isinstance(patterns, list):
        return any(p.lower() in line.lower() for p in patterns)
    else:
        return patterns.lower() in line.lower()


def test_rule_against_log(sigma_rule, log_lines):
    """
    Test satu Sigma rule terhadap log lines.

    Untuk testing dengan raw log (belum ter-parse oleh SIEM),
    kita match pattern sebagai keyword di seluruh line.

    Support:
    - Simple condition: 1 selection group
    - AND condition: selection1 and selection2 (semua group harus match di line yang sama)
    - OR condition: 1 of selection_* (minimal 1 group match)
    """
    detection = sigma_rule.get('detection', {})
    condition = detection.get('condition', '')

    # Pisahkan selection groups (key yang mulai dengan "selection" atau "filter")
    groups = {}
    for key, value in detection.items():
        if key in ('condition', 'timeframe'):
            continue
        # Hanya ambil key yang berisi list/dict pattern (bukan modifier meta)
        if isinstance(value, dict):
            # Flatten: ambil semua values dari semua fields di group
            all_patterns = []
            for field, patterns in value.items():
                if isinstance(patterns, list):
                    all_patterns.extend(patterns)
                else:
                    all_patterns.append(patterns)
            groups[key] = all_patterns
        elif isinstance(value, (list, str)):
            groups[key] = value

    matches = []

    for i, line in enumerate(log_lines):
        # Hitung match per group
        group_results = {}
        for group_name, patterns in groups.items():
            group_results[group_name] = line_matches_keyword(line, patterns)

        # Evaluate condition
        is_match = False

        if 'and not' in condition.lower():
            # e.g., "selection1 and selection2 and not filter"
            parts_and = condition.lower().split(' and not ')
            positive_part = parts_and[0]
            filter_part = parts_and[1] if len(parts_and) > 1 else ''

            # Positive: semua group di positive_part harus match
            positive_groups = [g.strip() for g in positive_part.split(' and ')]
            is_positive = all(
                group_results.get(g, False) for g in positive_groups
            )

            # Filter: jika filter match, exclude
            is_filtered = any(
                group_results.get(g.strip(), False)
                for g in filter_part.split(' or ')
            )

            is_match = is_positive and not is_filtered

        elif ' and ' in condition.lower():
            # e.g., "selection1 and selection2"
            groups_needed = [g.strip() for g in condition.lower().split(' and ')]
            is_match = all(group_results.get(g, False) for g in groups_needed)

        elif ' or ' in condition.lower():
            groups_needed = [g.strip() for g in condition.lower().split(' or ')]
            is_match = any(group_results.get(g, False) for g in groups_needed)

        elif condition.lower().startswith('1 of '):
            # e.g., "1 of selection_*"
            prefix = condition.lower().replace('1 of ', '').replace('*', '')
            matching_groups = [
                v for k, v in group_results.items()
                if k.startswith(prefix) and v
            ]
            is_match = len(matching_groups) >= 1

        elif condition.lower().startswith('all of '):
            prefix = condition.lower().replace('all of ', '').replace('*', '')
            matching_groups = [
                v for k, v in group_results.items()
                if k.startswith(prefix)
            ]
            is_match = len(matching_groups) > 0 and all(matching_groups)

        else:
            # Simple: single selection
            is_match = any(group_results.values())

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
    print("  Detection Rule Tester")
    print("=" * 60)

    if not RULES_DIR.exists():
        print(f"[-] Rules folder not found: {RULES_DIR}")
        return

    total_rules = 0
    total_matches = 0
    total_no_match = 0
    total_errors = 0

    for rule_file in sorted(RULES_DIR.rglob("*.yml")):
        print(f"\n[TEST] {rule_file.name}")

        try:
            sigma_rule = load_sigma_rule(rule_file)
        except Exception as e:
            print(f"  [ERROR] Cannot load rule: {e}")
            total_errors += 1
            continue

        # Cari sample log yang sesuai
        logsource = sigma_rule.get('logsource', {})
        service = logsource.get('service', '')

        log_filename = LOG_MAP.get(service, 'auth.log')
        log_file = SAMPLE_LOGS_DIR / log_filename

        if not log_file.exists():
            print(f"  [SKIP] No sample log: {log_filename}")
            continue

        log_lines = load_sample_log(log_file)

        # Test rule
        matches = test_rule_against_log(sigma_rule, log_lines)

        if matches:
            print(f"  [PASS] Found {len(matches)} match(es):")
            for m in matches:
                print(f"    Line {m['line_number']}: {m['log'][:80]}")
            total_matches += len(matches)
        else:
            print(f"  [WARN] No matches found")
            total_no_match += 1

        total_rules += 1

    print(f"\n{'=' * 60}")
    print(f"  Summary:")
    print(f"    Rules tested:  {total_rules}")
    print(f"    Total matches: {total_matches}")
    print(f"    No match:      {total_no_match}")
    print(f"    Errors:        {total_errors}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    run_all_tests()
