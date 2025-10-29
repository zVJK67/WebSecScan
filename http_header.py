import re
from typing import Dict, List, Any
from colorama import Fore, Style

"""
http_header.py — improved HTTP security header analyzer

Usage:
    findings = analyze_security_headers(response.headers)
    print_findings(findings)
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
            "Severity": "High",
            "Recommendation": "Add a CSP header to control sources of scripts, styles, and media."
        })
    else:
        # use regex to detect unsafe tokens robustly
        if re.search(r"(?:'|\")?unsafe-inline(?:'|\")?", csp, re.IGNORECASE) or re.search(r"(?:'|\")?unsafe-eval(?:'|\")?", csp, re.IGNORECASE):
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Avoid 'unsafe-inline' and 'unsafe-eval' in CSP. Use nonces/hashes or stricter directives.",
                "Detail": csp
            })
        else:
            # check presence of at least a default-src or script-src directive
            if not re.search(r"(?:^|\s)(default-src|script-src)\s", csp, re.IGNORECASE):
                findings.append({
                    "Header": "Content-Security-Policy",
                    "Status": "Misconfigured",
                    "Severity": "Medium",
                    "Recommendation": "CSP present but lacks default-src or script-src directive; add explicit directives.",
                    "Detail": csp
                })
            else:
                findings.append({
                    "Header": "Content-Security-Policy",
                    "Status": "Present",
                    "Severity": "Low",
                    "Recommendation": "CSP found. Review directives for overly permissive sources.",
                    "Detail": csp
                })

    # --- Strict Transport Security (HSTS) ---
    hsts = hdr("Strict-Transport-Security")
    if not hsts:
        findings.append({
            "Header": "Strict-Transport-Security",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Enable HSTS (Strict-Transport-Security) to enforce HTTPS and prevent downgrade attacks."
        })
    else:
        # try to extract max-age
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if not m:
            findings.append({
                "Header": "Strict-Transport-Security",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Add 'max-age' directive (e.g., max-age=31536000) to HSTS for proper enforcement.",
                "Detail": hsts
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
                    "Severity": "Medium",
                    "Recommendation": "Increase HSTS max-age to at least 31536000 (1 year) and consider includeSubDomains + preload.",
                    "Detail": hsts
                })
            else:
                # check includeSubDomains and preload presence as recommendations
                subs = bool(re.search(r"includesubdomains", hsts, re.IGNORECASE))
                preload = bool(re.search(r"\bpreload\b", hsts, re.IGNORECASE))
                recs = []
                if not subs:
                    recs.append("includeSubDomains")
                if not preload:
                    recs.append("preload")
                findings.append({
                    "Header": "Strict-Transport-Security",
                    "Status": "Present",
                    "Severity": "Low" if subs and preload else "Medium",
                    "Recommendation": "HSTS configured. Consider adding: " + (", ".join(recs) if recs else "none (good)."),
                    "Detail": hsts
                })

    # --- X-Frame-Options ---
    xfo = hdr("X-Frame-Options")
    if not xfo:
        findings.append({
            "Header": "X-Frame-Options",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN to protect against clickjacking."
        })
    else:
        val = xfo.strip().upper()
        if val not in {"DENY", "SAMEORIGIN"}:
            # ALLOW-FROM is deprecated and rarely useful; report as misconfigured.
            findings.append({
                "Header": "X-Frame-Options",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN. 'ALLOW-FROM' is deprecated; prefer CSP frame-ancestors.",
                "Detail": xfo
            })
        else:
            findings.append({
                "Header": "X-Frame-Options",
                "Status": "Present",
                "Severity": "Low",
                "Recommendation": "X-Frame-Options set appropriately.",
                "Detail": xfo
            })

    # --- X-XSS-Protection ---
    xxp = hdr("X-XSS-Protection")
    if not xxp:
        # modern guidance: this header is deprecated; report as low severity missing for legacy browsers
        findings.append({
            "Header": "X-XSS-Protection",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "X-XSS-Protection is largely deprecated in modern browsers. If supporting legacy browsers, consider '1; mode=block'."
        })
    else:
        # flag if value not the recommended legacy value
        if xxp.strip() != "1; mode=block":
            findings.append({
                "Header": "X-XSS-Protection",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "For legacy browsers use 'X-XSS-Protection: 1; mode=block' if desired, but note this header is deprecated.",
                "Detail": xxp
            })
        else:
            findings.append({
                "Header": "X-XSS-Protection",
                "Status": "Present",
                "Severity": "Low",
                "Recommendation": "Legacy XSS protection header present.",
                "Detail": xxp
            })

    # --- X-Content-Type-Options ---
    xcto = hdr("X-Content-Type-Options")
    if not xcto:
        findings.append({
            "Header": "X-Content-Type-Options",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add X-Content-Type-Options: nosniff to prevent MIME-type confusion."
        })
    else:
        if xcto.strip().lower() != "nosniff":
            findings.append({
                "Header": "X-Content-Type-Options",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Ensure X-Content-Type-Options is set to 'nosniff'.",
                "Detail": xcto
            })
        else:
            findings.append({
                "Header": "X-Content-Type-Options",
                "Status": "Present",
                "Severity": "Low",
                "Recommendation": "Configured correctly.",
                "Detail": xcto
            })

    # --- Referrer Policy ---
    rp = hdr("Referrer-Policy")
    if not rp:
        findings.append({
            "Header": "Referrer-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add Referrer-Policy (recommended: strict-origin-when-cross-origin or no-referrer)."
        })
    else:
        rp_val = rp.strip().lower()
        allowed_policies = {
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin"
        }
        if rp_val not in allowed_policies:
            findings.append({
                "Header": "Referrer-Policy",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Use a known referrer policy such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
                "Detail": rp
            })
        else:
            # mark certain policies as weak
            if rp_val == "no-referrer-when-downgrade":
                findings.append({
                    "Header": "Referrer-Policy",
                    "Status": "Present (weak)",
                    "Severity": "Low",
                    "Recommendation": "Consider 'strict-origin-when-cross-origin' or 'no-referrer' for stronger privacy.",
                    "Detail": rp
                })
            else:
                findings.append({
                    "Header": "Referrer-Policy",
                    "Status": "Present",
                    "Severity": "Low",
                    "Recommendation": "Referrer-Policy looks acceptable.",
                    "Detail": rp
                })

    # --- Permissions-Policy (formerly Feature-Policy) ---
    pp = hdr("Permissions-Policy") or hdr("Feature-Policy")
    if not pp:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add Permissions-Policy to control access to powerful features (camera, microphone, geolocation)."
        })
    else:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Present",
            "Severity": "Low",
            "Recommendation": "Review Permissions-Policy to ensure only required features are allowed.",
            "Detail": pp
        })

    # --- COEP / COOP / CORP ---
    coep = hdr("Cross-Origin-Embedder-Policy")
    coop = hdr("Cross-Origin-Opener-Policy")
    corp = hdr("Cross-Origin-Resource-Policy")

    if not coep:
        findings.append({
            "Header": "Cross-Origin-Embedder-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Consider adding Cross-Origin-Embedder-Policy (e.g., 'require-corp') if using cross-origin isolation."
        })
    else:
        findings.append({
            "Header": "Cross-Origin-Embedder-Policy",
            "Status": "Present",
            "Severity": "Low",
            "Recommendation": "Verify COEP value (e.g., 'require-corp').",
            "Detail": coep
        })

    if not coop:
        findings.append({
            "Header": "Cross-Origin-Opener-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Consider adding Cross-Origin-Opener-Policy: same-origin to improve isolation against side-channel attacks."
        })
    else:
        findings.append({
            "Header": "Cross-Origin-Opener-Policy",
            "Status": "Present",
            "Severity": "Low",
            "Recommendation": "Verify COOP value (e.g., 'same-origin' or 'same-origin-allow-popups').",
            "Detail": coop
        })

    if not corp:
        findings.append({
            "Header": "Cross-Origin-Resource-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Consider Cross-Origin-Resource-Policy to restrict which origins can load resources."
        })
    else:
        findings.append({
            "Header": "Cross-Origin-Resource-Policy",
            "Status": "Present",
            "Severity": "Low",
            "Recommendation": "Verify CORP value (e.g., 'same-origin' or 'same-site').",
            "Detail": corp
        })

    # --- Server Information Disclosure ---
    server = hdr("Server")
    if server:
        # lightweight parse to extract product/version (useful for fingerprinting reporting)
        m = re.search(r'^\s*([^/\s]+)(?:/([\d\.]+))?', server)
        parsed = {"raw": server}
        if m:
            parsed["product"] = m.group(1)
            parsed["version"] = m.group(2)
        findings.append({
            "Header": "Server",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Avoid exposing the Server header to reduce fingerprinting and information disclosure.",
            "Detail": parsed
        })

    # --- Allow Header Disclosure ---
    allow = hdr("Allow")
    if allow:
        # parse and normalize methods
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        findings.append({
            "Header": "Allow",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Avoid exposing the 'Allow' header as it reveals supported HTTP methods. Review allowed methods.",
            "Detail": methods
        })

    return findings


def print_findings(findings: List[Dict[str, Any]]) -> None:
    """
    Nicely print the findings produced by analyze_security_headers.
    """
    missing = [f for f in findings if f["Status"].lower() == "missing"]
    misconfigured = [f for f in findings if f["Status"].lower() == "misconfigured"]
    # include "present (weak)" or other statuses as misconfigured-ish if needed
    present_weak = [f for f in findings if "weak" in f.get("Status", "").lower()]

    total_issues = len(missing) + len(misconfigured) + len(present_weak)

    # Top framing
    print("\n" + Fore.MAGENTA + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print(Fore.CYAN + "🛡️ Security Header Analysis Results" + Style.RESET_ALL)
    print("════════════════════════════════════════════════════════════════")
    print(Fore.WHITE + f"Total Issues Detected: {Fore.YELLOW}{total_issues}{Style.RESET_ALL}")
    print(Fore.WHITE + f"Missing Headers: {Fore.RED}{len(missing)}{Style.RESET_ALL} | Misconfigured: {Fore.YELLOW}{len(misconfigured)}\n")

    def print_group(title: str, items: List[Dict[str, Any]], color: str) -> None:
        if not items:
            return
        print(color + f"{title}:" + Style.RESET_ALL)
        print(color + "────────────────────────" + Style.RESET_ALL)
        for i, f in enumerate(items, 1):
            severity_color = {
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }.get(f.get("Severity", "Low"), Fore.WHITE)

            print(f"{Fore.WHITE}{i}. {f['Header']}")
            print(f"   {severity_color}Severity: {f.get('Severity', 'Low')}{Style.RESET_ALL}")
            rec = f.get("Recommendation", "")
            print(f"{Fore.CYAN}   Recommendation: {rec}{Style.RESET_ALL}")
            if "Detail" in f:
                print(f"   {Fore.WHITE}Detail: {f['Detail']}{Style.RESET_ALL}")
            print()

    # Print groups
    print_group("🚫 Missing Headers", missing, Fore.RED)
    print_group("⚠️ Misconfigured Headers", misconfigured + present_weak, Fore.YELLOW)

    if not missing and not misconfigured and not present_weak:
        print(Fore.GREEN + "\n✅ All security headers are properly configured!\n" + Style.RESET_ALL)

    # bottom framing
    print(Fore.MAGENTA + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
