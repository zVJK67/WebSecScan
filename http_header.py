#http_header.py
import re
from typing import Dict, List, Any
from colorama import Fore, Style

"""
http_header.py — improved HTTP security header analyzer

Usage:
    findings = analyze_security_headers(response.headers)
    print_findings(findings, response.headers)
"""

def analyze_security_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Analyze a headers mapping for common security header issues.

    - headers: mapping-like object (case-insensitive expected). We normalize to lowercase keys internally.
    - returns: list of findings dicts with keys: Header, Status, Severity, Recommendation, (optional) Detail
    """
    findings: List[Dict[str, Any]] = []

    # Normalize header keys to lowercase for robust lookup
    lower_headers = {k.lower(): (v if v is not None else "") for k, v in headers.items()}

    def hdr(name: str) -> str:
        return lower_headers.get(name.lower(), "")

    # --- Content Security Policy (CSP) ---
    csp = hdr("Content-Security-Policy")
    if not csp:
        findings.append({
            "Header": "Content-Security-Policy",
            "Status": "Missing",
            "Recommendation": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'"
        })
    else:
        # use regex to detect unsafe tokens robustly
        if re.search(r"(?:'|\")?unsafe-inline(?:'|\")?", csp, re.IGNORECASE) or re.search(r"(?:'|\")?unsafe-eval(?:'|\")?", csp, re.IGNORECASE):
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Misconfigured",
                "Recommendation": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
                "CurrentValue": csp
            })
        else:
            # check presence of at least a default-src or script-src directive
            if not re.search(r"(?:^|\s)(default-src|script-src)\s", csp, re.IGNORECASE):
                findings.append({
                    "Header": "Content-Security-Policy",
                    "Status": "Misconfigured",
                    "Recommendation": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
                    "CurrentValue": csp
                })

    # --- Strict Transport Security (HSTS) ---
    hsts = hdr("Strict-Transport-Security")
    if not hsts:
        findings.append({
            "Header": "Strict-Transport-Security",
            "Status": "Missing",
            "Recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        })
    else:
        # try to extract max-age
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if not m:
            findings.append({
                "Header": "Strict-Transport-Security",
                "Status": "Misconfigured",
                "Recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "CurrentValue": hsts
            })
        else:
            try:
                max_age = int(m.group(1))
            except ValueError:
                max_age = 0
            # recommended at least 1 year (31536000 seconds)
            if max_age < 31536000:
                findings.append({
                    "Header": "Strict-Transport-Security",
                    "Status": "Misconfigured",
                    "Recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    "CurrentValue": hsts
                })
            else:
                # check includeSubDomains presence
                if not re.search(r"includesubdomains", hsts, re.IGNORECASE):
                    findings.append({
                        "Header": "Strict-Transport-Security",
                        "Status": "Misconfigured",
                        "Recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                        "CurrentValue": hsts
                    })

    # --- X-Frame-Options ---
    xfo = hdr("X-Frame-Options")
    if not xfo:
        findings.append({
            "Header": "X-Frame-Options",
            "Status": "Missing",
            "Recommendation": "X-Frame-Options: SAMEORIGIN / DENY"
        })
    else:
        val = xfo.strip().upper()
        if val not in {"DENY", "SAMEORIGIN"}:
            # ALLOW-FROM is deprecated and rarely useful; report as misconfigured.
            findings.append({
                "Header": "X-Frame-Options",
                "Status": "Misconfigured",
                "Recommendation": "X-Frame-Options: SAMEORIGIN / DENY",
                "CurrentValue": xfo
            })

    # --- X-XSS-Protection ---
    xxp = hdr("X-XSS-Protection")
    if not xxp:
        # modern guidance: this header is deprecated; report as low severity missing for legacy browsers
        findings.append({
            "Header": "X-XSS-Protection",
            "Status": "Missing",
            "Recommendation": "X-XSS-Protection: 0"
        })
    else:
        # flag if value not the recommended value (should be 0 in modern practice)
        if xxp.strip() != "0":
            findings.append({
                "Header": "X-XSS-Protection",
                "Status": "Misconfigured",
                "Recommendation": "X-XSS-Protection: 0",
                "CurrentValue": xxp
            })

    # --- X-Content-Type-Options ---
    xcto = hdr("X-Content-Type-Options")
    if not xcto:
        findings.append({
            "Header": "X-Content-Type-Options",
            "Status": "Missing",
            "Recommendation": "X-Content-Type-Options: nosniff"
        })
    else:
        if xcto.strip().lower() != "nosniff":
            findings.append({
                "Header": "X-Content-Type-Options",
                "Status": "Misconfigured",
                "Recommendation": "X-Content-Type-Options: nosniff",
                "CurrentValue": xcto
            })

    # --- Cache-Control ---
    cc = hdr("Cache-Control")
    if not cc:
        findings.append({
            "Header": "Cache-Control",
            "Status": "Missing",
            "Recommendation": "Cache-Control: no-store, no-cache"
        })
    else:
        # Check if it contains no-store OR no-cache
        cc_lower = cc.lower()
        has_no_store = "no-store" in cc_lower
        has_no_cache = "no-cache" in cc_lower
        
        if not has_no_store and not has_no_cache:
            findings.append({
                "Header": "Cache-Control",
                "Status": "Misconfigured",
                "Recommendation": "Cache-Control: no-store, no-cache",
                "CurrentValue": cc
            })

    # --- Referrer Policy ---
    rp = hdr("Referrer-Policy")
    if not rp:
        findings.append({
            "Header": "Referrer-Policy",
            "Status": "Missing",
            "Recommendation": "Referrer-Policy: strict-origin-when-cross-origin"
        })
    else:
        rp_val = rp.strip().lower()
        # Best practice is strict-origin-when-cross-origin
        if rp_val != "strict-origin-when-cross-origin":
            findings.append({
                "Header": "Referrer-Policy",
                "Status": "Misconfigured",
                "Recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
                "CurrentValue": rp
            })

    # --- Content-Type ---
    ct = hdr("Content-Type")
    if not ct:
        findings.append({
            "Header": "Content-Type",
            "Status": "Missing",
            "Recommendation": "Content-Type: text/html; charset=UTF-8"
        })
    else:
        # Check for proper configuration - must match best practice exactly
        ct_lower = ct.lower().replace(" ", "")  # normalize spacing
        best_practice = "text/html;charset=utf-8"
        
        # Check if it matches best practice (allowing for spacing variations)
        if best_practice not in ct_lower:
            findings.append({
                "Header": "Content-Type",
                "Status": "Misconfigured",
                "Recommendation": "Content-Type: text/html; charset=UTF-8",
                "CurrentValue": ct
            })

    # --- Cross-Origin-Opener-Policy ---
    coop = hdr("Cross-Origin-Opener-Policy")
    if not coop:
        findings.append({
            "Header": "Cross-Origin-Opener-Policy",
            "Status": "Missing",
            "Recommendation": "Cross-Origin-Opener-Policy: same-origin"
        })
    else:
        coop_val = coop.strip().lower()
        # Best practice is same-origin
        if coop_val != "same-origin":
            findings.append({
                "Header": "Cross-Origin-Opener-Policy",
                "Status": "Misconfigured",
                "Recommendation": "Cross-Origin-Opener-Policy: same-origin",
                "CurrentValue": coop
            })

    # --- Cross-Origin-Embedder-Policy ---
    coep = hdr("Cross-Origin-Embedder-Policy")
    if not coep:
        findings.append({
            "Header": "Cross-Origin-Embedder-Policy",
            "Status": "Missing",
            "Recommendation": "Cross-Origin-Embedder-Policy: require-corp"
        })
    else:
        coep_val = coep.strip().lower()
        # Best practice is require-corp
        if coep_val != "require-corp":
            findings.append({
                "Header": "Cross-Origin-Embedder-Policy",
                "Status": "Misconfigured",
                "Recommendation": "Cross-Origin-Embedder-Policy: require-corp",
                "CurrentValue": coep
            })

    # --- Cross-Origin-Resource-Policy ---
    corp = hdr("Cross-Origin-Resource-Policy")
    if not corp:
        findings.append({
            "Header": "Cross-Origin-Resource-Policy",
            "Status": "Missing",
            "Recommendation": "Cross-Origin-Resource-Policy: same-site"
        })
    else:
        corp_val = corp.strip().lower()
        # Best practice is same-site
        if corp_val != "same-site":
            findings.append({
                "Header": "Cross-Origin-Resource-Policy",
                "Status": "Misconfigured",
                "Recommendation": "Cross-Origin-Resource-Policy: same-site",
                "CurrentValue": corp
            })

    # --- Permissions-Policy (formerly Feature-Policy) ---
    pp = hdr("Permissions-Policy") or hdr("Feature-Policy")
    if not pp:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Missing",
            "Recommendation": "Add Permissions-Policy to control access to powerful features (camera, microphone, geolocation)."
        })

    return findings


def print_findings(findings: List[Dict[str, Any]], raw_headers: Dict[str, str]) -> None:
    """
    Print the findings in the desired format with raw headers display.
    
    - findings: list of finding dictionaries from analyze_security_headers()
    - raw_headers: the original response headers dict to display
    """
    
    # Filter to only show Missing or Misconfigured items
    issues = [f for f in findings if f["Status"] in ["Missing", "Misconfigured"]]
    
    # Count by status
    missing_count = len([f for f in issues if f["Status"] == "Missing"])
    misconfigured_count = len([f for f in issues if f["Status"] == "Misconfigured"])
    
    # Print header
    print(Fore.CYAN + "HTTP Security Header Analysis Results" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    
    # Print raw response headers in asterisk box
    print(Fore.WHITE + "GET Response:" + Style.RESET_ALL)
    print(Fore.YELLOW + "*" * 60 + Style.RESET_ALL)
    for key, value in raw_headers.items():
        print(f"{key}: {value}")
    print(Fore.YELLOW + "*" * 60 + Style.RESET_ALL)
    
    # Print summary
    print(Fore.WHITE + f"\nTotal Issues Detected: {Fore.YELLOW}{len(issues)}{Style.RESET_ALL}")
    print(Fore.WHITE + f"Missing Headers: {Fore.RED}{missing_count}{Style.RESET_ALL} | " + 
          Fore.WHITE + f"Misconfigured: {Fore.YELLOW}{misconfigured_count}{Style.RESET_ALL}")
    
    # Print fixed Risk Rating
    print(Fore.WHITE + "\nRisk Rating:" + Style.RESET_ALL)
    print(Fore.WHITE + "Severity: Low" + Style.RESET_ALL)
    print(Fore.WHITE + "CVSS: 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)" + Style.RESET_ALL)
    
    # Print findings section with backticks separator
    print(Fore.WHITE + "\nFindings:" + Style.RESET_ALL)
    print(Fore.CYAN + "`" * 80 + Style.RESET_ALL)
    
    if not issues:
        print(Fore.GREEN + "✅ All security headers are properly configured!\n" + Style.RESET_ALL)
    else:
        # Print each finding (no severity displayed)
        for idx, finding in enumerate(issues, 1):
            print(f"{Fore.WHITE}{idx}. {finding['Header']}{Style.RESET_ALL}")
            print(f"   {Fore.WHITE}Issue: {finding['Status']}{Style.RESET_ALL}")
            
            # Show current value if misconfigured
            if finding["Status"] == "Misconfigured" and "CurrentValue" in finding:
                print(f"   {Fore.WHITE}Current Value: {finding['CurrentValue']}{Style.RESET_ALL}")
            
            print(f"   {Fore.WHITE}Recommendation: {finding['Recommendation']}{Style.RESET_ALL}\n")
    
    # Bottom border
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)