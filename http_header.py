# http_header.py
import re
from typing import Dict, List, Any
from colorama import Fore, Style

"""
http_header.py — improved HTTP security header analyzer

Note: This module intentionally does NOT assign per-finding severity.
Your system is categorical; only vulnerabilities (final findings) have a risk rating.
The Risk Rating printed here is kept fixed as in the original design.
"""

def analyze_security_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Analyze a headers mapping for common security header issues.

    - headers: mapping-like object (case-insensitive expected). We normalize to lowercase keys internally.
    - returns: list of findings dicts with keys: Header, Status, Recommendation, (optional) CurrentValue
    """
    findings: List[Dict[str, Any]] = []

    # Normalize header keys to lowercase for robust lookup
    lower_headers = {k.lower(): (v if v is not None else "") for k, v in headers.items()}

    def hdr(name: str) -> str:
        return lower_headers.get(name.lower(), "")

    # helper to append finding (no Severity field — categorical system)
    def add_finding(header_name: str, status: str, recommendation: str, current: str = None):
        finding = {
            "Header": header_name,
            "Status": status,
            "Recommendation": recommendation
        }
        if current is not None:
            finding["CurrentValue"] = current
        findings.append(finding)

    # --- Content Security Policy (CSP) ---
    csp = hdr("Content-Security-Policy")
    if not csp:
        add_finding("Content-Security-Policy", "Missing",
                    "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'")
    else:
        # detect unsafe tokens robustly
        if re.search(r"(?:'|\")?unsafe-inline(?:'|\")?", csp, re.IGNORECASE) or re.search(r"(?:'|\")?unsafe-eval(?:'|\")?", csp, re.IGNORECASE):
            add_finding("Content-Security-Policy", "Misconfigured",
                        "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'", current=csp)
        else:
            # check presence of at least a default-src or script-src directive
            if not re.search(r"(?:^|\s)(default-src|script-src)\s", csp, re.IGNORECASE):
                add_finding("Content-Security-Policy", "Misconfigured",
                            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'", current=csp)

    # --- Strict Transport Security (HSTS) ---
    hsts = hdr("Strict-Transport-Security")
    if not hsts:
        add_finding("Strict-Transport-Security", "Missing",
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains")
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if not m:
            add_finding("Strict-Transport-Security", "Misconfigured",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains", current=hsts)
        else:
            try:
                max_age = int(m.group(1))
            except ValueError:
                max_age = 0
            if max_age < 31536000:
                add_finding("Strict-Transport-Security", "Misconfigured",
                            "Strict-Transport-Security: max-age=31536000; includeSubDomains", current=hsts)
            else:
                if not re.search(r"includesubdomains", hsts, re.IGNORECASE):
                    add_finding("Strict-Transport-Security", "Misconfigured",
                                "Strict-Transport-Security: max-age=31536000; includeSubDomains", current=hsts)

    # --- X-Frame-Options ---
    xfo = hdr("X-Frame-Options")
    if not xfo:
        add_finding("X-Frame-Options", "Missing", "X-Frame-Options: SAMEORIGIN / DENY")
    else:
        val = xfo.strip().upper()
        if val not in {"DENY", "SAMEORIGIN"}:
            add_finding("X-Frame-Options", "Misconfigured", "X-Frame-Options: SAMEORIGIN / DENY", current=xfo)

    # --- X-XSS-Protection ---
    xxp = hdr("X-XSS-Protection")
    if not xxp:
        # modern guidance: deprecated header; report as Low-style missing for legacy browsers
        add_finding("X-XSS-Protection", "Missing", "X-XSS-Protection: 0")
    else:
        val = xxp.strip()
        # Treat '0' as recommended; treat '1; mode=block' as legacy (flag informational/misconfigured)
        if val == "0":
            pass
        elif val.lower().startswith("1"):
            add_finding("X-XSS-Protection", "Misconfigured", "X-XSS-Protection: 0 (modern best practice)", current=xxp)
        else:
            add_finding("X-XSS-Protection", "Misconfigured", "X-XSS-Protection: 0", current=xxp)

    # --- X-Content-Type-Options ---
    xcto = hdr("X-Content-Type-Options")
    if not xcto:
        add_finding("X-Content-Type-Options", "Missing", "X-Content-Type-Options: nosniff")
    else:
        if xcto.strip().lower() != "nosniff":
            add_finding("X-Content-Type-Options", "Misconfigured", "X-Content-Type-Options: nosniff", current=xcto)

    # --- Cache-Control ---
    cc = hdr("Cache-Control")
    if not cc:
        add_finding("Cache-Control", "Missing", "Cache-Control: no-store, no-cache")
    else:
        cc_lower = cc.lower()
        has_no_store = "no-store" in cc_lower
        has_no_cache = "no-cache" in cc_lower
        if not has_no_store and not has_no_cache:
            add_finding("Cache-Control", "Misconfigured", "Cache-Control: no-store, no-cache", current=cc)

    # --- Referrer Policy ---
    rp = hdr("Referrer-Policy")
    if not rp:
        add_finding("Referrer-Policy", "Missing", "Referrer-Policy: strict-origin-when-cross-origin")
    else:
        rp_val = rp.strip().lower()
        if rp_val != "strict-origin-when-cross-origin":
            add_finding("Referrer-Policy", "Misconfigured", "Referrer-Policy: strict-origin-when-cross-origin", current=rp)

    # --- Content-Type ---
    ct = hdr("Content-Type")
    if not ct:
        add_finding("Content-Type", "Missing", "Content-Type: text/html; charset=UTF-8")
    else:
        ct_lower = ct.lower().replace(" ", "")
        best_practice = "text/html;charset=utf-8"
        if best_practice not in ct_lower:
            add_finding("Content-Type", "Misconfigured", "Content-Type: text/html; charset=UTF-8", current=ct)

    # --- Cross-Origin-Opener-Policy ---
    coop = hdr("Cross-Origin-Opener-Policy")
    if not coop:
        add_finding("Cross-Origin-Opener-Policy", "Missing", "Cross-Origin-Opener-Policy: same-origin")
    else:
        coop_val = coop.strip().lower()
        if coop_val != "same-origin":
            add_finding("Cross-Origin-Opener-Policy", "Misconfigured", "Cross-Origin-Opener-Policy: same-origin", current=coop)

    # --- Cross-Origin-Embedder-Policy ---
    coep = hdr("Cross-Origin-Embedder-Policy")
    if not coep:
        add_finding("Cross-Origin-Embedder-Policy", "Missing", "Cross-Origin-Embedder-Policy: require-corp")
    else:
        coep_val = coep.strip().lower()
        if coep_val != "require-corp":
            add_finding("Cross-Origin-Embedder-Policy", "Misconfigured", "Cross-Origin-Embedder-Policy: require-corp", current=coep)

    # --- Cross-Origin-Resource-Policy ---
    corp = hdr("Cross-Origin-Resource-Policy")
    if not corp:
        add_finding("Cross-Origin-Resource-Policy", "Missing", "Cross-Origin-Resource-Policy: same-site")
    else:
        corp_val = corp.strip().lower()
        if corp_val != "same-site":
            add_finding("Cross-Origin-Resource-Policy", "Misconfigured", "Cross-Origin-Resource-Policy: same-site", current=corp)

    # --- Permissions-Policy (formerly Feature-Policy) ---
    pp = hdr("Permissions-Policy") or hdr("Feature-Policy")
    if not pp:
        add_finding("Permissions-Policy", "Missing", "Add Permissions-Policy to control access to powerful features (camera, microphone, geolocation).")

    return findings


def print_findings(findings: List[Dict[str, Any]], raw_headers: Dict[str, str], verbose: bool = False) -> None:
    """
    Print findings with either:
      - FULL RAW HEADERS (verbose=True)
      - COMPACT SUMMARY HEADERS (verbose=False)
    """

    # Only Missing or Misconfigured findings
    issues = [f for f in findings if f.get("Status") in ["Missing", "Misconfigured"]]

    missing_count = len([f for f in issues if f.get("Status") == "Missing"])
    misconfigured_count = len([f for f in issues if f.get("Status") == "Misconfigured"])

    # Header lines
    print(Fore.CYAN + "\nHTTP Security Header Analysis Results" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    # ============================================================
    # VERBOSE MODE — show RAW HEADERS EXACTLY as received
    # ============================================================
    if verbose:
        print(Fore.WHITE + "GET Response (raw headers):" + Style.RESET_ALL)
        print(Fore.YELLOW + "*" * 60 + Style.RESET_ALL)
        for key, value in raw_headers.items():
            print(f"{key}: {value}")
        print(Fore.YELLOW + "*" * 60 + Style.RESET_ALL)

    # ============================================================
    # NON-VERBOSE MODE — show SUMMARY-ONLY headers
    # ============================================================
    else:
        print(Fore.WHITE + "GET Response (summary headers):" + Style.RESET_ALL)
        print(Fore.YELLOW + "*" * 60 + Style.RESET_ALL)

        keys_of_interest = [
            "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
            "X-XSS-Protection", "X-Content-Type-Options", "Cache-Control",
            "Referrer-Policy", "Content-Type", "Permissions-Policy"
        ]

        for k in keys_of_interest:
            v = raw_headers.get(k) or raw_headers.get(k.lower()) or "(not set)"
            print(f"{k}: {v}")

        print(Fore.YELLOW + "*" * 60 + Style.RESET_ALL)

    # Summary line
    print(Fore.WHITE + f"\nTotal Issues Detected: {Fore.YELLOW}{len(issues)}{Style.RESET_ALL}")
    print(Fore.WHITE + f"Missing Headers: {Fore.RED}{missing_count}{Style.RESET_ALL} | "
          f"Misconfigured: {Fore.YELLOW}{misconfigured_count}{Style.RESET_ALL}")

    # Fixed risk rating (your system is categorical; do not change)
    print(Fore.WHITE + "\nRisk Rating:" + Style.RESET_ALL)
    print(Fore.WHITE + "Severity: Low" + Style.RESET_ALL)
    print(Fore.WHITE + "CVSS: 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)" + Style.RESET_ALL)

    # Findings section
    print(Fore.WHITE + "\nFindings:" + Style.RESET_ALL)
    print(Fore.CYAN + "`" * 80 + Style.RESET_ALL)

    if not issues:
        print(Fore.GREEN + "✓ All security headers are properly configured!\n" + Style.RESET_ALL)
    else:
        for idx, finding in enumerate(issues, 1):
            print(f"{Fore.WHITE}{idx}. {finding['Header']}{Style.RESET_ALL}")
            print(f"   Issue: {finding['Status']}")

            if "CurrentValue" in finding:
                print(f"   Current Value: {finding['CurrentValue']}")

            print(f"   Recommendation: {finding['Recommendation']}\n")

    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

