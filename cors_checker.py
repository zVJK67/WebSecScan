import requests
from colorama import Fore, Style

def analyze_cors(url):
    """
    Analyze CORS configuration for potential misconfigurations.
    Returns a list of findings with severity for summary aggregation.
    """
    print(Fore.CYAN + "\n🌍 CORS Security Analysis")
    print("=" * 36)

    fake_origin = "https://evil-attacker.com"
    headers = {"Origin": fake_origin}
    findings = []

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to check CORS: {e}" + Style.RESET_ALL)
        return findings

    allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
    allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")
    allow_methods = response.headers.get("Access-Control-Allow-Methods", "")

    print(Fore.WHITE + "\n📋 CORS Response Headers:")
    print("-" * 36)
    print(f"Access-Control-Allow-Origin: {allow_origin or 'N/A'}")
    print(f"Access-Control-Allow-Credentials: {allow_credentials or 'N/A'}")
    print(f"Access-Control-Allow-Methods: {allow_methods or 'N/A'}")
    print("-" * 36)

    # === Misconfiguration Detection ===
    if not allow_origin:
        findings.append({
            "Category": "CORS",
            "Description": "CORS not configured (no Access-Control-Allow-Origin header).",
            "Severity": "Low"
        })
        print(Fore.YELLOW + "[!] No Access-Control-Allow-Origin header found. CORS may not be enabled." + Style.RESET_ALL)
    else:
        if allow_origin == "*":
            if allow_credentials.lower() == "true":
                findings.append({
                    "Category": "CORS",
                    "Description": "Wildcard origin ('*') combined with credentials allowed — severe misconfiguration.",
                    "Severity": "High"
                })
                print(Fore.RED + "[CRITICAL] Wildcard origin with credentials allowed!" + Style.RESET_ALL)
            else:
                findings.append({
                    "Category": "CORS",
                    "Description": "Wildcard origin allowed ('*') — potential data exposure risk.",
                    "Severity": "Medium"
                })
                print(Fore.YELLOW + "[!] Wildcard origin detected ('*')." + Style.RESET_ALL)
        elif fake_origin in allow_origin:
            findings.append({
                "Category": "CORS",
                "Description": f"Server reflects arbitrary origin ({fake_origin}) — possible CORS misconfiguration.",
                "Severity": "High"
            })
            print(Fore.RED + "[!] Server reflected attacker-controlled Origin. Potential CORS bypass." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[+] Origin not reflected. CORS seems properly restricted." + Style.RESET_ALL)

    print(Fore.GREEN + "\n✅ CORS analysis completed.\n" + Style.RESET_ALL)
    return findings
