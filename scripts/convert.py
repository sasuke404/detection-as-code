#!/usr/bin/env python3
"""
Sigma to Wazuh Rule Converter
=============================
Baca semua Sigma rules (YAML) dari folder rules/,
convert ke format Wazuh XML, simpan di folder wazuh_rules/.
"""

import os
import sys
import yaml
import hashlib
from pathlib import Path
from datetime import datetime

RULES_DIR = Path(__file__).parent.parent / "rules"
OUTPUT_DIR = Path(__file__).parent.parent / "wazuh_rules"

LEVEL_MAP = {
    'critical': 12,
    'high': 10,
    'medium': 7,
    'low': 3
}


def load_sigma_rule(file_path):
    """Baca Sigma rule dari YAML file."""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def generate_rule_id(title):
    """Generate numeric ID dari hash title (Wazuh butuh angka)."""
    return abs(hash(title)) % 90000 + 10000


def sigma_to_wazuh(sigma_rule):
    """
    Convert Sigma rule dict ke Wazuh XML format.

    Wazuh rule format:
    <rule id="ID" level="LEVEL">
        <description>...</description>
        <group>...</group>
        <field name="...">pattern</field>
        <mitre><id>...</id></mitre>
    </rule>
    """
    rule_id = generate_rule_id(sigma_rule['title'])
    wazuh_level = LEVEL_MAP.get(sigma_rule.get('level', 'medium'), 7)

    detection = sigma_rule.get('detection', {})
    selection = detection.get('selection', {})

    # Build field matches
    fields_xml = ""
    for field, value in selection.items():
        clean_field = field.split('|')[0]

        if isinstance(value, list):
            for v in value:
                fields_xml += f'        <field name="{clean_field}">{v}</field>\n'
        else:
            fields_xml += f'        <field name="{clean_field}">{value}</field>\n'

    # MITRE tags
    mitre_ids = ""
    for tag in sigma_rule.get('tags', []):
        if tag.startswith('attack.t'):
            technique = tag.replace('attack.', '')
            mitre_ids += f'        <id>{technique}</id>\n'

    # Group (tactic)
    group = 'unknown'
    for tag in sigma_rule.get('tags', []):
        if tag.startswith('attack.') and not tag.startswith('attack.t'):
            group = tag.replace('attack.', '')
            break

    # Timeframe
    timeframe = detection.get('timeframe', '')
    timeframe_xml = f'        <timeframe>{timeframe}</timeframe>\n' if timeframe else ''

    # Build full XML
    wazuh_xml = f"""<rule id="{rule_id}" level="{wazuh_level}">
    <description>{sigma_rule['title']}</description>
    <group>{group}</group>
{timeframe_xml}{fields_xml}    <mitre>
{mitre_ids}    </mitre>
</rule>"""

    return wazuh_xml, rule_id


def process_all_rules():
    """Process semua Sigma rules di folder rules/."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    if not RULES_DIR.exists():
        print(f"[-] Rules folder not found: {RULES_DIR}")
        sys.exit(1)

    rules_processed = 0
    rules_failed = 0

    print("=" * 60)
    print("  Sigma to Wazuh Rule Converter")
    print("=" * 60)

    for rule_file in sorted(RULES_DIR.rglob("*.yml")):
        try:
            print(f"\n[+] Processing: {rule_file.name}")

            sigma_rule = load_sigma_rule(rule_file)
            wazuh_xml, rule_id = sigma_to_wazuh(sigma_rule)

            output_file = OUTPUT_DIR / f"{rule_file.stem}.xml"
            with open(output_file, 'w') as f:
                f.write(wazuh_xml)

            print(f"    ID: {rule_id}")
            print(f"    Level: {sigma_rule.get('level', 'medium')} -> {LEVEL_MAP.get(sigma_rule.get('level', 'medium'), 7)}")
            print(f"    Output: {output_file.name}")

            rules_processed += 1

        except Exception as e:
            print(f"    [ERROR] {e}")
            rules_failed += 1

    print(f"\n{'=' * 60}")
    print(f"  Summary: {rules_processed} converted, {rules_failed} failed")
    print(f"  Output: {OUTPUT_DIR}")
    print(f"{'=' * 60}")

    return rules_processed, rules_failed


if __name__ == "__main__":
    process_all_rules()
