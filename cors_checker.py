'''
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

    # Extract headers safely
    allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
    allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")
    allow_methods = response.headers.get("Access-Control-Allow-Methods", "")
    vary_header = response.headers.get("Vary", "")

    # Show CORS response headers
    print(Fore.WHITE + "\n📋 CORS Response Headers:")
    print("-" * 36)
    print(f"Access-Control-Allow-Origin: {allow_origin or 'N/A'}")
    print(f"Access-Control-Allow-Credentials: {allow_credentials or 'N/A'}")
    print(f"Access-Control-Allow-Methods: {allow_methods or 'N/A'}")
    print(f"Vary: {vary_header or 'N/A'}")
    print("-" * 36)

    # === Misconfiguration Detection ===
    if not allow_origin:
        findings.append({
            "Category": "CORS",
            "Description": "CORS not configured (no Access-Control-Allow-Origin header).",
            "Severity": "Low",
            "Recommendation": "Add Access-Control-Allow-Origin for controlled cross-domain resource sharing."
        })
        print(Fore.YELLOW + "[!] No Access-Control-Allow-Origin header found. CORS may not be enabled." + Style.RESET_ALL)

    else:
        if allow_origin == "*":
            if allow_credentials.lower() == "true":
                findings.append({
                    "Category": "CORS",
                    "Description": "Wildcard origin ('*') combined with credentials allowed — severe misconfiguration.",
                    "Severity": "High",
                    "Recommendation": "Never use '*' with Access-Control-Allow-Credentials: true. Use specific origins."
                })
                print(Fore.RED + "[CRITICAL] Wildcard origin with credentials allowed!" + Style.RESET_ALL)
            else:
                findings.append({
                    "Category": "CORS",
                    "Description": "Wildcard origin allowed ('*') — potential data exposure risk.",
                    "Severity": "Medium",
                    "Recommendation": "Avoid wildcard origin ('*'). Specify trusted origins explicitly."
                })
                print(Fore.YELLOW + "[!] Wildcard origin detected ('*')." + Style.RESET_ALL)

        elif fake_origin in allow_origin:
            findings.append({
                "Category": "CORS",
                "Description": f"Server reflects arbitrary origin ({fake_origin}) — possible CORS misconfiguration.",
                "Severity": "High",
                "Recommendation": "Do not dynamically reflect Origin headers. Use strict whitelisting."
            })
            print(Fore.RED + "[!] Server reflected attacker-controlled Origin. Potential CORS bypass." + Style.RESET_ALL)

        else:
            print(Fore.GREEN + "[+] Origin not reflected. CORS seems properly restricted." + Style.RESET_ALL)

    # === Check for missing 'Vary: Origin' header ===
    if allow_origin and "*" not in allow_origin and "Origin" not in vary_header:
        findings.append({
            "Category": "CORS",
            "Description": "Missing 'Vary: Origin' header with specific origin — could cause caching vulnerabilities.",
            "Severity": "Low",
            "Recommendation": "Add 'Vary: Origin' when responding with specific Access-Control-Allow-Origin values."
        })
        print(Fore.YELLOW + "[!] Missing 'Vary: Origin' — caching issues possible for dynamic CORS responses." + Style.RESET_ALL)

    print(Fore.GREEN + "\n✅ CORS analysis completed.\n" + Style.RESET_ALL)
    return findings
'''

import requests
from colorama import Fore, Style

def analyze_cors(url):
    """
    CORS analysis that shows:
      1) original GET response (no Origin header)
      2) original OPTIONS response (no Origin)
      3) probe GET and probe OPTIONS with a malicious Origin
    Then it prints findings based on the observed headers.
    """
    print(Fore.CYAN + "\n🌍 CORS Security Analysis (Detailed View)")
    print("=" * 60)

    fake_origin = "https://evil-attacker.com"
    findings = []

    try:
        # 1) Original GET (no Origin)
        orig_get = requests.get(url, timeout=10)

        # 2) Original OPTIONS (no Origin) - some servers may respond differently
        orig_options = requests.options(url, timeout=10)

        # 3) Probe GET with attacker Origin (simple request)
        probe_get = requests.get(url, headers={"Origin": fake_origin}, timeout=10)

        # 4) Probe OPTIONS (preflight) with attacker Origin
        probe_options = requests.options(url, headers={
            "Origin": fake_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Test-Header"
        }, timeout=10)

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to perform CORS checks: {e}" + Style.RESET_ALL)
        return findings

    # Helper to pretty-print a subset of CORS headers from a response
    def cors_headers_from(resp):
        return {
            "Access-Control-Allow-Origin": resp.headers.get("Access-Control-Allow-Origin"),
            "Access-Control-Allow-Credentials": resp.headers.get("Access-Control-Allow-Credentials"),
            "Access-Control-Allow-Methods": resp.headers.get("Access-Control-Allow-Methods"),
            "Vary": resp.headers.get("Vary"),
            "Access-Control-Max-Age": resp.headers.get("Access-Control-Max-Age")
        }

    # Gather headers
    orig_get_h = cors_headers_from(orig_get)
    orig_options_h = cors_headers_from(orig_options)
    probe_get_h = cors_headers_from(probe_get)
    probe_options_h = cors_headers_from(probe_options)

    # --- 1) Show Original GET response headers (no Origin sent) ---
    print(Fore.WHITE + "\n1) Original GET response (no Origin header sent):")
    print("-" * 60)
    for k, v in orig_get_h.items():
        print(f"{k}: {v or 'N/A'}")
    print("-" * 60)

    # --- 2) Show Original OPTIONS response headers (no Origin) ---
    print(Fore.WHITE + "\n2) Original OPTIONS response (no Origin header sent):")
    print("-" * 60)
    for k, v in orig_options_h.items():
        print(f"{k}: {v or 'N/A'}")
    print("-" * 60)

    # --- 3) Show Probe GET response headers (we sent attacker Origin) ---
    print(Fore.WHITE + f"\n3) Probe GET response (Origin: {fake_origin}):")
    print("-" * 60)
    for k, v in probe_get_h.items():
        print(f"{k}: {v or 'N/A'}")
    print("-" * 60)

    # --- 4) Show Probe OPTIONS (preflight) response headers (we sent attacker Origin) ---
    print(Fore.WHITE + f"\n4) Probe OPTIONS response (Origin: {fake_origin} preflight):")
    print("-" * 60)
    for k, v in probe_options_h.items():
        print(f"{k}: {v or 'N/A'}")
    print("-" * 60)

    # --- Analysis / Findings ---
    print(Fore.WHITE + f"\n🔎 Analysis (based on probe and original responses):\n")

    # Prefer probe_options for methods if present, else probe_get, else original options
    allow_origin_probe = probe_options_h.get("Access-Control-Allow-Origin") or probe_get_h.get("Access-Control-Allow-Origin")
    allow_credentials_probe = probe_options_h.get("Access-Control-Allow-Credentials") or probe_get_h.get("Access-Control-Allow-Credentials")
    allow_methods_probe = probe_options_h.get("Access-Control-Allow-Methods") or probe_get_h.get("Access-Control-Allow-Methods")
    vary_probe = probe_options_h.get("Vary") or probe_get_h.get("Vary")

    # Immediate critical short-circuit: wildcard + credentials (any context)
    if (allow_origin_probe == "*" or orig_get_h.get("Access-Control-Allow-Origin") == "*"
        or orig_options_h.get("Access-Control-Allow-Origin") == "*") \
       and (allow_credentials_probe and allow_credentials_probe.lower() == "true"):
        findings.append({
            "Category": "CORS",
            "Description": "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true — invalid and critical.",
            "Severity": "High",
            "Context": "Observed in original or probe responses",
            "Recommendation": "Do not use '*' with credentials. Return explicit trusted origin(s) instead and ensure credentials are only allowed for those origins."
        })
        print(Fore.RED + "[CRITICAL] Detected Access-Control-Allow-Origin: *  AND  Access-Control-Allow-Credentials: true")
        print(Fore.RED + "→ Browsers disallow credentials with wildcard; this signals a server-side misconfiguration.\n" + Style.RESET_ALL)

    # If not short-circuited, continue deeper checks:
    # Check reflection: did the server echo our fake origin back?
    if allow_origin_probe:
        if fake_origin in str(allow_origin_probe):
            findings.append({
                "Category": "CORS",
                "Description": f"Server reflected attacker Origin ({fake_origin}) in Access-Control-Allow-Origin.",
                "Severity": "High",
                "Context": "Probe response",
                "Recommendation": "Do not reflect arbitrary Origin values. Use a strict server-side whitelist with absolute comparisons."
            })
            print(Fore.RED + f"[!] Server reflected attacker Origin in probe response: {allow_origin_probe}" + Style.RESET_ALL)
        elif allow_origin_probe == "*":
            # flagged earlier if credentials true; otherwise medium
            findings.append({
                "Category": "CORS",
                "Description": "Access-Control-Allow-Origin: * (wildcard) observed in probe response.",
                "Severity": "Medium",
                "Context": "Probe / Original responses",
                "Recommendation": "Avoid wildcard origins; use an explicit whitelist of trusted origins."
            })
            print(Fore.YELLOW + "[!] Access-Control-Allow-Origin: * observed in probe response." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[+] Probe response did not reflect attacker origin and did not return wildcard." + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] Probe did not return Access-Control-Allow-Origin header." + Style.RESET_ALL)
        findings.append({
            "Category": "CORS",
            "Description": "No Access-Control-Allow-Origin returned in probe response.",
            "Severity": "Low",
            "Context": "Probe response",
            "Recommendation": "If cross-origin access is required, use a strict whitelist and return that origin explicitly."
        })

    # Vary: Origin check when specific origin(s) are returned (avoid caching pitfalls)
    # We examine original and probe vary headers — prefer probe options
    vary_val = (probe_options_h.get("Vary") or probe_get_h.get("Vary") or orig_options_h.get("Vary") or orig_get_h.get("Vary") or "")
    if allow_origin_probe and "*" not in (allow_origin_probe or ""):
        if "origin" not in (vary_val or "").lower():
            findings.append({
                "Category": "CORS",
                "Description": "Missing 'Vary: Origin' when returning specific Access-Control-Allow-Origin values.",
                "Severity": "Medium",
                "Context": "Observed in responses (probe/original)",
                "Recommendation": "Add 'Vary: Origin' to prevent caching of a CORS response for multiple different origins."
            })
            print(Fore.YELLOW + "[!] Missing 'Vary: Origin' — caching issues possible for dynamic CORS responses." + Style.RESET_ALL)

    # Methods exposure: look at preflight probe OR original options
    methods_val = allow_methods_probe or orig_options_h.get("Access-Control-Allow-Methods") or ""
    if methods_val:
        methods_set = {m.strip().upper() for m in methods_val.split(",")}
        unsafe = {"PUT", "DELETE", "PATCH"}
        exposed = methods_set.intersection(unsafe)
        if exposed:
            findings.append({
                "Category": "CORS",
                "Description": f"Unsafe HTTP methods exposed via CORS or preflight: {', '.join(sorted(exposed))}",
                "Severity": "Medium",
                "Context": "Probe preflight or original OPTIONS",
                "Recommendation": "Avoid allowing unsafe methods cross-origin or require strict authentication/authorization."
            })
            print(Fore.YELLOW + f"[!] Unsafe methods exposed via CORS/preflight: {', '.join(sorted(exposed))}" + Style.RESET_ALL)

    # final summary header
    total = len(findings)
    print(Fore.WHITE + f"\nSummary: {total} CORS findings detected." + Style.RESET_ALL)
    if total:
        for i, f in enumerate(findings, 1):
            sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(f["Severity"], Fore.WHITE)
            print(f"\n{i}. {f['Category']} — {f['Description']}")
            print(f"   Severity: {sev_color}{f['Severity']}{Style.RESET_ALL}")
            if "Context" in f:
                print(f"   Context: {f['Context']}")
            print(f"   Recommendation: {f['Recommendation']}")

    else:
        print(Fore.GREEN + "No CORS issues detected.\n" + Style.RESET_ALL)

    print(Fore.CYAN + "\nCORS analysis completed.\n" + Style.RESET_ALL)
    return findings