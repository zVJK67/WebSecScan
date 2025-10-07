# analyze http headers
from colorama import Fore, Style

def analyze_security_headers(headers):
    """
    Analyze HTTP response headers for common security misconfigurations.
    Returns a list of findings (each as a dict with name, status, severity, and recommendation).
    """
    findings = []

    # --- Content Security Policy (CSP) ---
    csp = headers.get("Content-Security-Policy")
    if not csp:
        findings.append({
            "Header": "Content-Security-Policy",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Add a CSP header to control sources of scripts, styles, and media."
        })
    else:
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Avoid using 'unsafe-inline' or 'unsafe-eval' in CSP for stronger XSS protection."
            })
        else:
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Present",
                "Severity": "Low",
                "Recommendation": "CSP implemented properly."
            })

    # --- Strict Transport Security (HSTS) ---
    if "Strict-Transport-Security" not in headers:
        findings.append({
            "Header": "Strict-Transport-Security",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Enable HSTS to enforce HTTPS and protect against downgrade attacks."
        })
        #Strict-Transport-Security: max-age=86400; includeSubDomains

    # --- X-Frame-Options ---
    xfo = headers.get("X-Frame-Options")
    if not xfo:
        findings.append({
            "Header": "X-Frame-Options",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-Frame-Options: DENY to protect against clickjacking."
        })
    else:
        if xfo.strip().upper() != "DENY":
            findings.append({
                "Header": "X-Frame-Options",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Set X-Frame-Options to DENY for maximum protection against clickjacking."
            })

    # --- X-XSS-Protection ---
    xxp = headers.get("X-XXS-Protection")
    if not xxp:
        findings.append({
            "Header": "X-XXS-Protection",
            "Status": "Missing",
            "Severity": "Medium",#
            "Recommendation": "Set X-XXS-Protection : 0 to prevent against cross-site scripting (XSS) attack."
        })
    else:
        if xxp.strip().upper() != 0:
            findings.append({
                "Header": "X-XXS-Protection",
                "Status": "Misconfigured",
                "Severity": "Medium",#
                "Recommendation": "Set X-XXS-Protection : 0 to prevent against cross-site scripting (XSS) attack."
            })

    # --- X-Content-Type-Options ---
    xcto = headers.get("X-Content-Type-Options")
    if not xcto:
        findings.append({
            "Header": "X-Content-Type-Options",
            "Status": "Missing",
            "Severity": "Low",#
            "Recommendation": "Set X-Content-Type-Options : 0 to prevent MIME-type confusion."
        })
    else:
        if xcto.strip().upper() != 0:
            findings.append({
                "Header": "X-Content-Type-Options",
                "Status": "Misconfigured",
                "Severity": "Low",#
                "Recommendation": "Set X-XXS-Protection : 0 to prevent MIME-type confusion."
            })

    # --- Referrer Policy ---
    rp = headers.get("Referrer Policy")
    if not rp:
        findings.append({
            "Header": "Referrer-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer data leakage."
        })
    else:
        if rp.strip().upper() != "strict-origin-when-cross-origin":
            findings.append({
                "Header": "Referrer-Policy",
                "Status": "Misconfigured",
                "Severity": "Low",#
                "Recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer data leakage."
            })

    # --- Permissions Policy ---
    if "Permissions-Policy" not in headers:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Use Permissions-Policy to control access to browser features (e.g., camera, microphone)."
        })

    # --- Server ---
    if "Server" in headers:
        findings.append({
            "Header": "Server",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Dont show."
        })

    return findings

def print_findings(findings):
    """
    Print findings grouped by Missing and Misconfigured headers with color formatting.
    """
    # Group findings
    missing = [f for f in findings if f["Status"].lower() == "missing"]
    misconfigured = [f for f in findings if f["Status"].lower() in ("Misconfigured")]

    def print_group(title, items, color):
        if not items:
            return
        print(color + f"\n{title}:")
        print(color + "────────────────────────" + Style.RESET_ALL)
        for i, f in enumerate(items, 1):
            severity_color = {
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }.get(f["Severity"], Fore.WHITE)

            print(f"{Fore.WHITE}{i}. {f['Header']}")
            print(f"   {severity_color}Severity: {f['Severity']}")
            print(f"{Fore.CYAN}   Recommendation: {f['Recommendation']}\n")

    print(Fore.CYAN + "\n🛡️ Security Header Analysis Results" + Style.RESET_ALL)
    print("====================================")

    # Print missing and misconfigured headers
    print_group("🚫 Missing Headers", missing, Fore.RED)
    print_group("⚠️ Misconfigured Headers", misconfigured, Fore.YELLOW)

    # If nothing found
    if not missing and not misconfigured:
        print(Fore.GREEN + "\n✅ All security headers are properly configured!\n" + Style.RESET_ALL)
