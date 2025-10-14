import json
import requests
import os
import time
from collections import Counter

# Active les codes ANSI sur certains terminaux Windows
os.system('')

# Couleurs ANSI
COLORS = {
    "phishing": "\033[91m",     # Rouge
    "suspect": "\033[93m",      # Jaune
    "legitimate": "\033[92m",   # Vert
    "error": "\033[95m",        # Magenta
    "reset": "\033[0m"
}

# URLs de phishing connues
PHISHING_URLS = [
    "https://disney.plus-customers.help/login",
    "http://phishing-banque.ch",
    "http://faux-postfinance.ch/login",
    "http://secure-update.paypal.com-login.accountverify.ru",
    "http://appleid.apple.com-signin.verify-account.tk",
    "http://login-ch.postfinance.customer-update.io",
    "http://banking-verification.ubs.tk/account",
    "http://webmail-outlook-office365-login.com/login",
    "http://verify-facebook-securitycenter.com/reset",
    "http://dhl-package-tracker-support.com",
    "http://login-update-amazon.com-giftcard.tk",
    "http://swisscom-security-notification.ch-phish.net",
    "http://mail.swisspost.ch.security-verify.online",
    "http://malware.testing.google.test/testing/malware/",
    "http://115.63.37.181:38315/bin.sh",
    "http://urlhaus.abuse.ch/host/example.com/",
]

# Cas suspects / ambigus
SUSPECT_URLS = [
    "http://support-amazon.ch/reset-password",
    "http://ch.postfinance.com.security-check.xyz",
    "http://paypal-user-check.ch.account-verify.net",
    "http://info-login.ubs-online-support.ch",
    "http://ch.admin-verification.gov-login.com",
    "http://logmein-account-service.net/confirm",
    "http://secure-hosting.ch/account/login",
]

# Sites légitimes
LEGITIMATE_URLS = [
    "https://www.ubs.com",
    "https://www.postfinance.ch",
    "https://www.credit-suisse.com",
    "https://www.admin.ch",
    "https://www.swisscom.ch",
    "https://www.google.com",
    "https://www.apple.com",
    "https://www.wikipedia.org",
    "https://www.dhl.com",
    "https://www.microsoft.com",
]

# URLs trompeuses / techniques
EVASIVE_URLS = [
    "http://www.g00gle.com",
    "http://www.paypa1.com",
    "http://0x7F.0x0.0x0.0x1/login",                  # Encodage hexadécimal
    "http://google.com@malicious-site.com",          # username@host
    "http://verify-login.com?redirect=ubs.ch",       # avec redirection
    "http://ubs.ch.security.alerts.safe-login.com",  # sous-domaines
    "http://xn--pple-43d.com",                       # IDN homograph
    "http://login.admin.ch.verify.session.com",      # plausible mais faux
]

# Liste finale pour test
URLS_TO_TEST = PHISHING_URLS + SUSPECT_URLS + LEGITIMATE_URLS + EVASIVE_URLS

results_summary = Counter()

def print_result(url, status_code, result):
    verdict = result.get("verdict", "error")
    color = COLORS.get(verdict, COLORS["error"])
    print("=" * 70)
    print(f"[TEST] {url}")
    print(f"Status: {status_code}")
    print(color + json.dumps(result, indent=2, ensure_ascii=False) + COLORS["reset"])
    print()
    results_summary[verdict] += 1


def run_all_tests():
    api_url = "http://127.0.0.1:8001/check_url"
    print("\n=== Lancement des tests de détection de phishing ===\n")

    total = len(URLS_TO_TEST)
    errors = 0

    for i, test_url in enumerate(URLS_TO_TEST, 1):
        print(f"Test {i}/{total} : {test_url}")
        try:
            response = requests.post(api_url, json={"url": test_url}, timeout=10)
            if response.status_code != 200:
                print(COLORS["error"] + f"[ERREUR HTTP {response.status_code}] {test_url}" + COLORS["reset"])
                results_summary["error"] += 1
                errors += 1
                continue

            result = response.json()
            print_result(test_url, response.status_code, result)
        except Exception as e:
            print(COLORS["error"] + f"[EXCEPTION] {test_url} → {e}" + COLORS["reset"])
            results_summary["error"] += 1
            errors += 1

        time.sleep(0.2)  # Petite pause entre les requêtes

    # Résumé
    print("\n" + "=" * 70)
    print(f"[RÉSUMÉ] {total} tests effectués")
    for verdict, count in results_summary.items():
        color = COLORS.get(verdict, COLORS["reset"])
        print(f"{color}{verdict.upper():<12} : {count}{COLORS['reset']}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_all_tests()
