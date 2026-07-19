#!/usr/bin/env python3
"""
Wazuh Rule Deployer
===================
Deploy converted Wazuh rules (XML) ke Wazuh manager via REST API.
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
        """Login ke Wazuh API, dapatkan JWT token."""
        url = f"{self.api_url}/security/user/authenticate"
        try:
            resp = self.session.post(url, auth=(WAZUH_API_USER, WAZUH_API_PASS))
            if resp.status_code == 200:
                self.token = resp.json()['data']['token']
                self.session.headers['Authorization'] = f'Bearer {self.token}'
                print("[+] Authenticated to Wazuh API")
                return True
            else:
                print(f"[-] Auth failed: {resp.status_code} - {resp.text}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"[-] Cannot connect to {self.api_url}")
            print("    Is Wazuh running? Check URL and port.")
            return False
        except Exception as e:
            print(f"[-] Auth error: {e}")
            return False

    def deploy_rules(self):
        """Deploy semua XML rules ke Wazuh."""
        if not self.token:
            print("[-] Not authenticated. Call authenticate() first.")
            return False

        if not RULES_DIR.exists():
            print(f"[-] Rules output folder not found: {RULES_DIR}")
            print("    Run convert.py first!")
            return False

        rules_deployed = 0
        rules_failed = 0

        for rule_file in sorted(RULES_DIR.glob("*.xml")):
            try:
                print(f"\n[+] Deploying: {rule_file.name}")

                with open(rule_file, 'r') as f:
                    rule_content = f.read()

                # POST rule ke Wazuh API
                # Note: Endpoint bisa berbeda tergantung versi Wazuh
                url = f"{self.api_url}/rules/files/{rule_file.name}"

                resp = self.session.put(
                    url,
                    data=rule_content,
                    headers={'Content-Type': 'application/xml'}
                )

                if resp.status_code == 200:
                    print(f"    [OK] Deployed")
                    rules_deployed += 1
                else:
                    print(f"    [FAIL] {resp.status_code}: {resp.text[:200]}")
                    rules_failed += 1

            except Exception as e:
                print(f"    [ERROR] {e}")
                rules_failed += 1

        print(f"\n{'=' * 50}")
        print(f"  Deploy: {rules_deployed} ok, {rules_failed} failed")
        print(f"{'=' * 50}")

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
            print(f"[-] Restart error: {e}")
            return False


def main():
    print("=" * 50)
    print("  Wazuh Rule Deployer")
    print("=" * 50)

    if not RULES_DIR.exists():
        print(f"[-] No converted rules found: {RULES_DIR}")
        print("    Run convert.py first!")
        sys.exit(1)

    deployer = WazuhDeployer()

    # Step 1: Authenticate
    if not deployer.authenticate():
        print("\n[-] Cannot authenticate.")
        print("    Check: WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS")
        sys.exit(1)

    # Step 2: Deploy rules
    deployer.deploy_rules()

    # Step 3: Restart manager
    deployer.restart_manager()

    print("\n[+] Done! Check Wazuh dashboard for new rules.")


if __name__ == "__main__":
    main()
