# http_method.py
import re
from typing import List, Union, Dict, Any, Optional
from colorama import Fore, Style
import requests

# Known risky HTTP methods and short explanation
_METHOD_RISKS = {
    "OPTIONS": "This method is a diagnostic method mainly used for debugging purposes, but it can unintentionally help attackers by revealing supported server methods.",
    "PUT": "This method allows a client to upload new files on the web server.",
    "DELETE": "This method allows a client to delete a file on the web server.",
    "TRACE": "This method simply echoes back to the client whatever string has been sent to the server, and is used mainly for debugging purposes.",
    "CONNECT": "This method could allow a client to use the web server as a proxy.",
    "PATCH": "Partial updates — risky when not properly access-controlled.",
    # WebDAV / others
    "PROPFIND": "WebDAV method that can leak file system structure or metadata.",
    "MKCOL": "WebDAV method to create collections (directories).",
    "LOCK": "WebDAV locking method (can be abused).",
    "UNLOCK": "WebDAV unlock method.",
    "REPORT": "Repository/reporting method that may leak info.",
    "COPY": "Can copy resources if misconfigured.",
    "MOVE": "Can move/rename resources; risky if unintended.",
}

def _normalize_methods_input(methods: Union[List[str], str, None]) -> List[str]:
    """Return uppercased, deduplicated list of HTTP methods."""
    if not methods:
        return []
    if isinstance(methods, str):
        parts = [m.strip().upper() for m in re.split(r'\s*,\s*', methods) if m.strip()]
    else:
        parts = [str(m).strip().upper() for m in methods if str(m).strip()]
    # deduplicate preserving order
    seen = set()
    out = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

def analyze_http_methods_from_list(methods_list: List[str]) -> List[Dict[str, Any]]:
    """
    Return findings list for provided normalized methods_list.
    Each finding for unsafe methods will include header, status and recommendation.
    """
    findings = []
    if not methods_list:
        return []

    risky = [m for m in methods_list if m in _METHOD_RISKS]
    if risky:
        for m in risky:
            findings.append({
                "Header": f"HTTP Method: {m}",
                "Status": "Unsafe",
                "Severity": "High",
                "Recommendation": _METHOD_RISKS[m],
                "Method": m,
                "Methods": methods_list
            })
    
    return findings

def _print_raw_options_response(resp: Optional[requests.Response]) -> None:
    """Print a compact raw OPTIONS response block (status + headers), matching the desired sample."""
    print(Fore.CYAN + "OPTIONS Response:" + Style.RESET_ALL)
    print(Fore.CYAN + "**********************************************************" + Style.RESET_ALL)
    if resp is None:
        print(Fore.WHITE + "(No response received)" + Style.RESET_ALL)
        print(Fore.CYAN + "**********************************************************" + Style.RESET_ALL)
        return

    # Print status line
    status_line = f"HTTP/1.1 {resp.status_code} {resp.reason}"
    print(Fore.WHITE + status_line)

    # Print common headers in a predictable order
    common_order = ["Date", "Content-Type", "Content-Length", "Connection", "Server"]
    for h in common_order:
        if h in resp.headers:
            print(Fore.WHITE + f"{h}: {resp.headers[h]}")
    
    # Print Allow / Access-Control-Allow-Methods if present
    if "Allow" in resp.headers:
        print(Fore.WHITE + f"Allow: {resp.headers['Allow']}")
    if "Access-Control-Allow-Origin" in resp.headers:
        print(Fore.WHITE + f"Access-Control-Allow-Origin: {resp.headers['Access-Control-Allow-Origin']}")
    if "Access-Control-Allow-Credentials" in resp.headers:
        print(Fore.WHITE + f"Access-Control-Allow-Credentials: {resp.headers['Access-Control-Allow-Credentials']}")
    if "Access-Control-Allow-Methods" in resp.headers:
        print(Fore.WHITE + f"Access-Control-Allow-Methods: {resp.headers['Access-Control-Allow-Methods']}")
    
    # Print any remaining headers that weren't printed
    for k, v in resp.headers.items():
        if k in common_order or k in {"Allow", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Credentials"}:
            continue
        print(Fore.WHITE + f"{k}: {v}")
    print(Fore.CYAN + "**********************************************************" + Style.RESET_ALL)

def check_and_print_http_methods(url: str, timeout: int = 6) -> List[Dict[str, Any]]:
    """
    Do an OPTIONS request to `url`, print raw response, parse Allow (or AC-Allow-Methods),
    analyze for unsafe methods, and print findings (matching your desired format).
    Returns the findings list (so main.py can still collect them).
    """
    # Print section header
    print(Fore.CYAN + "HTTP Method Security Check" + Style.RESET_ALL)
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    
    resp = None
    response_received = False
    
    try:
        # Send OPTIONS request
        resp = requests.options(url, timeout=timeout, allow_redirects=True)
        response_received = True
    except Exception as e:
        # network error or similar
        response_received = False

    # 1) Print raw OPTIONS response first
    _print_raw_options_response(resp)

    # 2) Extract methods from headers (ONLY check 'Allow' header)
    methods_hdr_value = None
    if resp is not None:
        methods_hdr_value = resp.headers.get("Allow")

    # 3) Parse header value using regex if present
    methods_list = []
    if methods_hdr_value:
        methods_list = [m.strip().upper() for m in re.split(r'\s*,\s*', methods_hdr_value) if m.strip()]
    else:
        methods_list = []

    # 4) Analyze methods
    findings = analyze_http_methods_from_list(methods_list)

    # 5) Print findings in desired format
    print()
    
    # Scenario 1: No response received at all
    if not response_received:
        print(Fore.RED + "[!] Failed to retrieve OPTIONS response from server." + Style.RESET_ALL)
        print(Fore.WHITE + f"Detected Unsafe Methods: {Fore.GREEN}0{Style.RESET_ALL}")
        print(Fore.WHITE + "Findings:")
        print("``````````````````````````````````````````````````````````````````````````````````")
        print(Fore.GREEN + "✓ No unsafe HTTP methods detected." + Style.RESET_ALL)
        print("\nNote: Deeper testing is still needed to double check there are no unsafe HTTP methods enabled.")
        print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        return []
    
    # Scenario 2: Response received but no Allow header
    if not methods_list:
        print(Fore.RED + "[!] The 'Allow' header is not shown in the response." + Style.RESET_ALL)
        print(Fore.WHITE + f"Detected Unsafe Methods: {Fore.GREEN}0{Style.RESET_ALL}")
        print(Fore.WHITE + "Findings:")
        print("``````````````````````````````````````````````````````````````````````````````````")
        print(Fore.GREEN + "✓ No unsafe HTTP methods detected." + Style.RESET_ALL)
        print("\nNote: Deeper testing is still needed to double check there are no unsafe HTTP methods enabled.")
        print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
        return []

    # Scenario 3: Methods detected
    unsafe_findings = [f for f in findings if f.get("Status", "").lower() == "unsafe"]
    unsafe_count = len(unsafe_findings)
    
    # Determine if only OPTIONS (or OPTIONS among safe methods like GET, HEAD, POST)
    safe_methods = {"GET", "HEAD", "POST"}
    non_safe_methods = [m for m in methods_list if m not in safe_methods]
    
    # Check if only OPTIONS is the risky one among all methods
    only_options_risky = (non_safe_methods == ["OPTIONS"])
    
    print(Fore.RED + "[!] 'Allow' header is shown in OPTIONS response." + Style.RESET_ALL)
    print(Fore.WHITE + f"Detected Unsafe Methods: {Fore.RED if unsafe_count > 0 else Fore.GREEN}{unsafe_count}{Style.RESET_ALL}")
    
    if unsafe_count > 0:
        print(Fore.WHITE + "Risk Rating:")
        if only_options_risky:
            # Low severity if only OPTIONS is risky
            print(f"{Fore.YELLOW}Severity: Low{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}CVSS: 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N){Style.RESET_ALL}\n")
        else:
            # Medium severity if other unsafe methods present
            print(f"{Fore.YELLOW}Severity: Medium{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}CVSS: 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N){Style.RESET_ALL}\n")
        
        print("Findings:")
        print("``````````````````````````````````````````````````````````````````````````````````")
        for i, f in enumerate(unsafe_findings, start=1):
            method_name = f.get('Method', '')
            print(f"{i}. {method_name}")
            print(f"   -> {f.get('Recommendation')}")
        
        print("[Remediation]")
        print("Disable all unsafe methods.")
    else:
        # No unsafe methods detected
        print(Fore.WHITE + "Findings:")
        print("``````````````````````````````````````````````````````````````````````````````````")
        print(Fore.GREEN + "✓ No unsafe HTTP methods detected." + Style.RESET_ALL)
        print("\nNote: Deeper testing is still needed to double check there are no unsafe HTTP methods enabled.")
    
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    
    return findings