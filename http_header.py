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

def analyze_security_headers(headers: Dict[str, str], is_https: bool = True) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # Normalize headers
    lower_headers = {k.lower(): (v or "") for k, v in headers.items()}

    def hdr(name: str) -> str:
        return lower_headers.get(name.lower(), "")

    def add_finding(header: str, status: str, recommendation: str, current: str = None):
        item = {
            "Header": header,
            "Status": status,
            "Recommendation": recommendation
        }
        if current is not None:
            item["CurrentValue"] = current
        findings.append(item)

    # ============================================================
    # Content-Security-Policy
    # ============================================================
    csp = hdr("Content-Security-Policy")
    if not csp:
        add_finding(
            "Content-Security-Policy",
            "Missing",
            "Add CSP with default-src 'self' and frame-ancestors 'none'"
        )
    else:
        csp_lower = csp.lower()

        unsafe_inline = "unsafe-inline" in csp_lower
        unsafe_eval = "unsafe-eval" in csp_lower
        has_nonce_or_hash = bool(re.search(r"nonce-|sha256-|sha384-|sha512-", csp_lower))
        has_default_or_script = bool(re.search(r"(default-src|script-src)", csp_lower))
        has_frame_ancestors = "frame-ancestors" in csp_lower

        if (unsafe_inline or unsafe_eval) and not has_nonce_or_hash:
            add_finding(
                "Content-Security-Policy",
                "Misconfigured",
                "Avoid unsafe-inline/unsafe-eval; use nonces or hashes",
                csp
            )
        elif not has_default_or_script:
            add_finding(
                "Content-Security-Policy",
                "Misconfigured",
                "Define default-src or script-src directive",
                csp
            )
        elif not has_frame_ancestors:
            add_finding(
                "Content-Security-Policy",
                "Misconfigured",
                "Add frame-ancestors to prevent clickjacking",
                csp
            )

    # ============================================================
    # Strict-Transport-Security (HTTPS ONLY)
    # ============================================================
    hsts = hdr("Strict-Transport-Security")
    if is_https:
        if not hsts:
            add_finding(
                "Strict-Transport-Security",
                "Missing",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains"
            )
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if not m or int(m.group(1)) < 31536000:
                add_finding(
                    "Strict-Transport-Security",
                    "Misconfigured",
                    "Use max-age ≥ 31536000",
                    hsts
                )
            elif "includesubdomains" not in hsts.lower():
                add_finding(
                    "Strict-Transport-Security",
                    "Misconfigured",
                    "Add includeSubDomains",
                    hsts
                )

    # ============================================================
    # X-Frame-Options
    # ============================================================
    xfo = hdr("X-Frame-Options")
    if not xfo:
        add_finding("X-Frame-Options", "Missing", "X-Frame-Options: DENY or SAMEORIGIN")
    elif xfo.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        add_finding("X-Frame-Options", "Misconfigured", "Use DENY or SAMEORIGIN", xfo)

    # ============================================================
    # X-XSS-Protection (Deprecated → Informational)
    # ============================================================
    xxp = hdr("X-XSS-Protection")
    if xxp and not xxp.strip().startswith("0"):
        add_finding(
            "X-XSS-Protection",
            "Informational",
            "Deprecated header; modern browsers rely on CSP",
            xxp
        )

    # ============================================================
    # X-Content-Type-Options
    # ============================================================
    xcto = hdr("X-Content-Type-Options")
    if not xcto:
        add_finding("X-Content-Type-Options", "Missing", "X-Content-Type-Options: nosniff")
    elif xcto.strip().lower() != "nosniff":
        add_finding("X-Content-Type-Options", "Misconfigured", "Use nosniff", xcto)

    # ============================================================
    # Cache-Control (Context Aware)
    # ============================================================
    cc = hdr("Cache-Control")
    ct = hdr("Content-Type").lower()
    has_cookie = "set-cookie" in lower_headers

    if ("text/html" in ct or has_cookie):
        if not cc:
            add_finding("Cache-Control", "Missing", "Cache-Control: no-store, no-cache")
        elif not any(d in cc.lower() for d in ["no-store", "no-cache"]):
            add_finding("Cache-Control", "Misconfigured", "Disable caching for sensitive content. Set Cache-Control: no-store, no-cache", cc)

    # ============================================================
    # Referrer-Policy
    # ============================================================
    rp = hdr("Referrer-Policy")
    if not rp:
        add_finding(
            "Referrer-Policy",
            "Missing",
            "Referrer-Policy: strict-origin-when-cross-origin"
        )

    # ============================================================
    # Cross-Origin Policies
    # ============================================================
    coop = hdr("Cross-Origin-Opener-Policy")
    coep = hdr("Cross-Origin-Embedder-Policy")

    if not coop:
        add_finding("Cross-Origin-Opener-Policy", "Missing", "Cross-Origin-Opener-Policy: same-origin")
    elif coop.lower() != "same-origin":
        add_finding("Cross-Origin-Opener-Policy", "Misconfigured", "Use same-origin", coop)

    if not coep:
        add_finding("Cross-Origin-Embedder-Policy", "Missing", "Cross-Origin-Embedder-Policy: require-corp")
    elif coep.lower() != "require-corp":
        add_finding("Cross-Origin-Embedder-Policy", "Misconfigured", "Use require-corp", coep)

    if coep.lower() == "require-corp" and coop.lower() != "same-origin":
        add_finding(
            "COOP/COEP",
            "Misconfigured",
            "COEP=require-corp should be paired with COOP=same-origin"
        )

    # ============================================================
    # X-DNS-Prefetch-Control (Privacy)
    # ============================================================
    dns_prefetch = hdr("X-DNS-Prefetch-Control")
    if not dns_prefetch:
        add_finding(
            "X-DNS-Prefetch-Control",
            "Informational",
            "Consider X-DNS-Prefetch-Control: off for privacy"
        )

    # ============================================================
    # Permissions-Policy
    # ============================================================
    pp = hdr("Permissions-Policy") or hdr("Feature-Policy")
    if not pp:
        add_finding(
            "Permissions-Policy",
            "Missing",
            "Restrict browser features such as camera, microphone, geolocation"
        )

    return findings


def print_findings(findings: List[Dict[str, Any]], raw_headers: Dict[str, str], verbose: bool = False) -> None:
    """
    Print findings with either:
      - FULL RAW HEADERS (verbose=True)
      - COMPACT SUMMARY HEADERS (verbose=False)
    """

    # Only Missing or Misconfigured findings
    issues = [f for f in findings if f.get("Status") in ["Missing", "Misconfigured", "Informational"]]

    missing_count = len([f for f in issues if f.get("Status") == "Missing"])
    misconfigured_count = len([f for f in issues if f.get("Status") == "Misconfigured"])
    info_count = len([f for f in findings if f.get("Status") == "Informational"])

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
    print(Fore.WHITE + f"Informational Findings: {Fore.CYAN}{info_count}{Style.RESET_ALL}")

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

def get_findings_for_export(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert header findings into export format.
    Informational findings are preserved but do NOT increase risk.
    """
    exported = []

    for f in findings:
        status = f.get("Status", "").lower()

        # Map status to severity (categorical-safe)
        if status == "informational":
            severity = "Info"
        elif status in ("missing", "misconfigured"):
            severity = "Low"
        else:
            severity = "Low"

        exported.append({
            "Category": "HTTP Security Headers",
            "Header": f.get("Header", ""),
            "Finding": f.get("Status", ""),
            "_item_short": f.get("Header", ""),  # Used for ItemDetails enrichment
            "Status": f.get("Status", ""),
            "CurrentValue": f.get("CurrentValue"),
            "Severity": severity
        })

    return exported
