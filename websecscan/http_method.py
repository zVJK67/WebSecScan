import re
from typing import List, Union, Dict, Any, Optional
from colorama import Fore, Style
import requests

"""
HTTP Method Security Checker

Design Notes:
- Passive detection only (OPTIONS-based)
- No active method execution to avoid side effects
- WebDAV methods are detected but not exploited
- Severity and CVSS are context-aware
- Risk rating is shown ONLY when findings exist
- Aligned with OWASP ZAP HTTP Method Scan
"""

# Known risky HTTP methods and explanations
_METHOD_RISKS = {
    "OPTIONS": "Reveals supported HTTP methods and may aid reconnaissance.",
    "PUT": "Allows file upload or overwrite if improperly restricted.",
    "DELETE": "Allows deletion of server-side resources.",
    "PATCH": "Allows partial modification of resources if not access-controlled.",

    # Contextual / lower confidence
    "TRACE": "Low risk; may enable cross-site tracing in legacy environments.",
    "CONNECT": "Risky only if the server can be abused as an open proxy.",

    # WebDAV
    "PROPFIND": "WebDAV method that may disclose directory structure or metadata.",
    "MKCOL": "WebDAV method that can create server-side collections.",
    "LOCK": "WebDAV locking method that may be abused.",
    "UNLOCK": "WebDAV unlock method.",
    "COPY": "Can copy resources if WebDAV is misconfigured.",
    "MOVE": "Can move or rename resources if WebDAV is enabled.",
}

SAFE_METHODS = {"GET", "HEAD", "POST"}
WEBDAV_METHODS = {"PROPFIND", "MKCOL", "LOCK", "UNLOCK", "COPY", "MOVE"}


def _normalize_methods_input(methods: Union[List[str], str, None]) -> List[str]:
    """Return uppercased, deduplicated list of HTTP methods."""
    if not methods:
        return []

    if isinstance(methods, str):
        parts = [m.strip().upper() for m in re.split(r"\s*,\s*", methods) if m.strip()]
    else:
        parts = [str(m).strip().upper() for m in methods if str(m).strip()]

    seen = set()
    out = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _calculate_severity(methods: List[str]) -> str:
    """Context-aware severity calculation."""
    non_safe = [m for m in methods if m not in SAFE_METHODS]

    if not non_safe:
        return "Info"

    if non_safe == ["OPTIONS"]:
        return "Low"

    webdav_count = len([m for m in non_safe if m in WEBDAV_METHODS])
    if webdav_count >= 2:
        return "Medium"

    if any(m in {"PUT", "DELETE", "MOVE", "COPY"} for m in non_safe):
        return "Medium"

    return "Low"


def _severity_to_cvss(severity: str) -> str:
    """Map severity to OWASP-style CVSS."""
    mapping = {
        "Low": "3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Medium": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "High": "8.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    }
    return mapping.get(severity, "—")


def analyze_http_methods_from_list(methods_list: List[str]) -> List[Dict[str, Any]]:
    """Generate findings for exposed HTTP methods."""
    findings = []
    if not methods_list:
        return findings

    severity = _calculate_severity(methods_list)
    risky_methods = [m for m in methods_list if m in _METHOD_RISKS]

    for m in risky_methods:
        findings.append({
            "Category": "HTTP Methods",
            "Header": f"HTTP Method: {m}",
            "_item_short": m,
            "Method": m,
            "Status": "Unsafe",
            "Severity": severity,
            "Recommendation": _METHOD_RISKS[m],
            "Methods": methods_list
        })

    return findings


def _print_raw_options_response(resp: Optional[requests.Response]) -> None:
    """Print raw OPTIONS response (status + headers)."""
    print(Fore.WHITE + "OPTIONS Response:" + Style.RESET_ALL)
    print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)

    if resp is None:
        print("(No response received)")
        print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)
        return

    print(Fore.WHITE + f"HTTP/1.1 {resp.status_code} {resp.reason}")

    ordered_headers = [
        "Date", "Server", "Allow",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Credentials",
        "Content-Type", "Content-Length", "Connection"
    ]

    printed = set()
    for h in ordered_headers:
        if h in resp.headers:
            print(Fore.WHITE + f"{h}: {resp.headers[h]}")
            printed.add(h)

    for k, v in resp.headers.items():
        if k not in printed:
            print(Fore.WHITE + f"{k}: {v}")

    print(Fore.CYAN + "**********************************************************" + Style.RESET_ALL)


def check_and_print_http_methods(url: str, timeout: int = 6, verbose: bool = False) -> List[Dict[str, Any]]:
    """Perform passive HTTP method analysis via OPTIONS."""
    print(Fore.CYAN + "\nHTTP Method Security Check" + Style.RESET_ALL)
    print(Fore.MAGENTA + "══════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    resp = None
    try:
        resp = requests.options(url, timeout=timeout, allow_redirects=True, verify=False)
    except requests.exceptions.RequestException as e:
        print(Fore.YELLOW + f"⚠️ OPTIONS request failed: {e}" + Style.RESET_ALL)

    if verbose:
        _print_raw_options_response(resp)

    methods_hdr = resp.headers.get("Allow") if resp else None
    methods_list = _normalize_methods_input(methods_hdr)

    # No Allow header → unknown exposure
    if not methods_list:
        print(Fore.YELLOW + "[!] Server did not disclose supported HTTP methods." + Style.RESET_ALL)
        print("Note: Absence of Allow header does not guarantee security.")
        print(Fore.MAGENTA + "══════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        return []

    findings = analyze_http_methods_from_list(methods_list)
    unsafe_methods = [m for m in methods_list if m not in SAFE_METHODS]

    if verbose:
        print(Fore.RED + "[!] 'Allow' header disclosed supported HTTP methods." + Style.RESET_ALL)
        print(f"Detected Potentially Unsafe Methods: {len(unsafe_methods)}")

    # ✅ Risk rating ONLY if findings exist
    if findings:
        severity = findings[0]["Severity"]
        cvss = _severity_to_cvss(severity)

        print(Fore.WHITE + "\nRisk Rating:" + Style.RESET_ALL)
        print(f"{Fore.YELLOW}Severity: {severity}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}CVSS: {cvss}{Style.RESET_ALL}")

    print("\nFindings:")
    print("``````````````````````````````````````````````````````````")
    if findings:
        for i, f in enumerate(findings, 1):
            print(f"{i}. {f['Method']}")
            print(f"   -> {f['Recommendation']}")
            if f["Method"] == "PROPFIND":
                print("   -> Note: Verify that 'Depth: infinity' is restricted (manual check).")
    else:
        print(Fore.GREEN + "✓ No unsafe HTTP methods detected." + Style.RESET_ALL)
        print("Note: Deeper testing may still be required.")

    print("\n[Remediation]")
    print("Disable unused or unsafe HTTP methods at the web server or application level.")
    print("Use allowlists and proper access controls.")

    print(Fore.MAGENTA + "══════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    return findings
